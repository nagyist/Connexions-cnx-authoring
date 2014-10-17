# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2013, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
import datetime
import io
import json
import re
try:
    import urllib2 # python2
except ImportError:
    import urllib.request as urllib2 # renamed in python3
try:
    import urlparse # python2
except ImportError:
    import urllib.parse as urlparse # renamed in python3

import cnxepub
import requests
from pyramid.threadlocal import get_current_registry
from cnxquerygrammar.query_parser import grammar, DictFormater
from parsimonious.exceptions import IncompleteParseError


def utf8(item):
    if isinstance(item, list):
        return [utf8(i) for i in item]
    if isinstance(item, dict):
        return {utf8(k): utf8(v) for k, v in item.items()}
    try: 
        return item.decode('utf-8')
    except: # bare except since this method is supposed to be safe anywhere
        return item


def change_dict_keys(data, func):
    for k in data.keys():
        _k = func(k)
        if _k != k:
            data[_k] = data.pop(k)
        if isinstance(data[_k], dict):
            change_dict_keys(data[_k], func)
        if isinstance(data[_k], list):
            for i in data[_k]:
                if isinstance(i, dict):
                    change_dict_keys(i, func)


def camelcase_to_underscore(camelcase):
    def replace(match):
        char = match.group(1)
        return '_{}'.format(char.lower())
    return re.sub('([A-Z])', replace, camelcase)

def underscore_to_camelcase(underscore):
    def replace(match):
        char = match.group(1)
        return '{}'.format(char.upper())
    return re.sub('_([a-z])', replace, underscore)

def structured_query(query_string):
    try:
        node_tree = grammar.parse(query_string)
    except IncompleteParseError:
        query_string = fix_quotes(query_string)
        node_tree = grammar.parse(query_string)
    return DictFormater().visit(node_tree)

def fix_quotes(query_string):
    # Attempt to fix unbalanced quotes in query_string

    if query_string.count('"') % 2 == 0:
        # no unbalanced quotes to fix
        return query_string

    fields = [] # contains what's matched by the regexp
    # e.g. fields = ['sort:pubDate', 'author:"first last"']
    def f(match):
        fields.append(match.string[match.start():match.end()])
        return ''

    # terms will be all the search terms that don't have a field
    terms = re.sub(r'[^\s:]*:("[^"]*"|[^\s]*)', f, query_string)
    query_string = '{}" {}'.format(terms.strip(), ' '.join(fields))
    return query_string

def filter_binder_documents(binder, documents):
    """walks through a binder, converting any draft documents that are
        not in the list of documents into documentpointers."""
    docids = [d.id for d in documents]
    for i, model in enumerate(binder):
        if isinstance(model, cnxepub.models.TranslucentBinder): # section/subcollection
            filter_binder_documents(model, documents)

        elif isinstance(model,cnxepub.models.Document):
            if model.id not in docids:
                binder.pop(i) # remove it
                # Is it new?
                if model.get_uri('cnx-archive'):
                    #convert to documentpointer
                    dp = epub.models.DocumentPointer(model.get_uri('cnx-archive'))
                    binder.insert(i,dp)

def build_epub(contents, submitter, submitlog):
    from .models import DEFAULT_LICENSE, Binder

    epub = io.BytesIO()
    documents = []
    binders = []
    for i,content in enumerate(contents,1):
        if type(content) == list: # book + pages in a list
            if isinstance(content[0], Binder): 
                filter_binder_documents(content[0], content[1:])
                content[0].publish_prep()
                binders.append(content[0])
            else:  # belt and suspenders - seems to be an extra level of lists - filter out docs
                for doc in content:
                    if isinstance(doc,cnxepub.models.Document):
                        doc.publish_prep()
                        documents.append(doc)
        elif isinstance(content, Binder): # Special case: toplevel is book + pages
            content.publish_prep()
            filter_binder_documents(content, contents[i:])
            binders.append(content)
            break # eat the whole list
        elif isinstance(content,cnxepub.models.Document):
            content.publish_prep()
            documents.append(content)
        

    if documents:
        license_text = ' '.join([DEFAULT_LICENSE.name, DEFAULT_LICENSE.abbr,
            DEFAULT_LICENSE.version])
        binders.append(cnxepub.models.TranslucentBinder(
                metadata={
                    'title': 'Publications binder',
                    'created': datetime.datetime.now(),
                    'revised': datetime.datetime.now(),
                    'license_text': license_text,
                    'license_url': DEFAULT_LICENSE.url,
                    },
                nodes=documents))
    cnxepub.adapters.make_publication_epub(
            binders, submitter, submitlog, epub)
    epub.seek(0)
    return epub


def fetch_archive_content(request, archive_id, extras=False):
    from .models import DocumentNotFoundError

    settings = request.registry.settings
    archive_url = settings['archive.url']
    if extras:
        content_url = urlparse.urljoin(archive_url,
                '/extras/{}'.format(archive_id))
    else:
        content_url = urlparse.urljoin(archive_url,
                '/contents/{}.json'.format(archive_id))
    try:
        response = urllib2.urlopen(content_url).read()
    except urllib2.HTTPError:
        raise DocumentNotFoundError(archive_id)
    try:
        document = json.loads(response.decode('utf-8'))
    except (TypeError, ValueError):
        raise DocumentNotFoundError(archive_id)
    change_dict_keys(document, camelcase_to_underscore)
    return document


def derive_resources(request, document):
    from .models import Resource

    settings = request.registry.settings
    archive_url = settings['archive.url']
    path = urlparse.unquote(request.route_path('get-resource', hash='{}'))
    resources = {}
    for r in document.references:
        if r.uri.startswith('/resources'):
            if not resources.get(r.uri):
                try:
                    response = urllib2.urlopen(urlparse.urljoin(archive_url, r.uri))
                except urllib2.HTTPError:
                    continue
                content_type = response.info().getheader('Content-Type')
                resources[r.uri] = Resource(content_type,
                        io.BytesIO(response.read()))
                yield resources[r.uri]
            r.bind(resources[r.uri], path)
    document.metadata['content'] = document.html


def profile_to_user_dict(profile):
    """Take a profile from openstax accounts and transform it into a local user
    format"""
    # in case it's already in the local user format, no need to transform
    if 'email' in profile:
        return profile
    email = None
    for contact_info in profile.get('contact_infos') or []:
        if contact_info.get('type') == 'EmailAddress':
            email = contact_info.get('value')
    firstname = profile.get('first_name') or ''
    surname = profile.get('last_name') or ''
    return {
            'firstname': firstname,
            'surname': surname,
            'email': email or '',
            'id': profile.get('username') or '',
            'fullname': profile.get('fullname',
                u'{} {}'.format(firstname, surname).strip()),
            }

def update_containment(binder, deletion = False):
    """updates the containment status of all draft documents in this binder"""
    from .storage import storage

    b_id = binder.id
    doc_ids = []
    old_docs = storage.get_all(contained_in = b_id)

    # additions
    if not deletion:
        docs = cnxepub.flatten_to_documents(binder)
        for doc in docs:
            doc_ids.append(doc.id) # gather for subtractions below
            if b_id not in doc.metadata['contained_in']:
                doc.metadata['contained_in'].append(b_id)
                storage.update(doc)
    # subtractions
    for doc in old_docs:
        if doc.id not in doc_ids:
            if b_id in doc.metadata['contained_in']:
                doc.metadata['contained_in'].remove(b_id)
                storage.update(doc)

def create_acl_for(request, document, uids):
    """Submit content identifiers to publishing and allow users to
    publish
    """
    from .models import PublishingError

    settings = request.registry.settings
    publishing_url = settings['publishing.url']
    api_key = settings['publishing.api_key']
    headers = {
            'x-api-key': api_key,
            'content-type': 'application/json',
            }
    payload = [{'uid': uid, 'permission': 'publish'} for uid in uids]

    acl_url = urlparse.urljoin(
            publishing_url, '/contents/{}/permissions'.format(document.id))
    response = requests.post(
            acl_url, data=json.dumps(payload), headers=headers)
    if response.status_code != 202:
        raise PublishingError(response)

def get_acl_for(request, document):
    """Get document ACL from publishing"""
    from .models import PublishingError

    settings = request.registry.settings
    publishing_url = settings['publishing.url']
    api_key = settings['publishing.api_key']
    headers = {
            'x-api-key': api_key,
            'content-type': 'application/json',
            }
    acl_url = urlparse.urljoin(
            publishing_url, '/contents/{}/permissions'.format(document.id))

    response = requests.get(acl_url)
    if response.status_code != 200:
        raise PublishingError(response)
    acl = response.json()
    document.acls = [(user_permission['uid'], 'view', 'edit', 'publish')
                     for user_permission in acl]

def get_roles(document, uid):
    field_to_roles = (
            ('publishers', 'Publisher'),
            ('editors', 'Editor'),
            ('translators', 'Translator'),
            ('authors', 'Author'),
            )
    for field, role in field_to_roles:
        users = [u['id'] for u in document.metadata.get(field) or []]
        if uid in users:
            yield role

def accept_roles_and_license(request, document, uid):
    """Accept roles and license for document and user uid"""
    from .models import PublishingError

    settings = request.registry.settings
    publishing_url = settings['publishing.url']
    headers = {
            'x-api-key': settings['publishing.api_key'],
            'content-type': 'application/json',
            }

    # accept roles
    roles_url = urlparse.urljoin(
            publishing_url, '/contents/{}/roles'.format(document.id))
    payload = [{'uid': uid, 'role': role, 'has_accepted': True}
            for role in get_roles(document, uid)]
    response = requests.post(roles_url, data=json.dumps(payload),
            headers=headers)
    if response.status_code != 202:
        raise PublishingError(response)

    # accept license
    license_url = urlparse.urljoin(
            publishing_url, '/contents/{}/licensors'.format(document.id))
    payload = {
            'license_url': document.metadata['license'].url,
            'licensors': [{'uid': uid, 'has_accepted': True}],
            }
    response = requests.post(license_url, data=json.dumps(payload),
            headers=headers)
    if response.status_code != 202:
        raise PublishingError(response)


PUBLISHING_ROLES_MAPPING = {
    'Author': 'authors',
    'Copyright Holder': 'licensors',
    'Editor': 'editors',
    'Illustrator': 'illustrators',
    'Publisher': 'publishers',
    'Translator': 'translators',
    }


def declare_roles(model):
    """Annotate the roles to include role acceptance information.
    The model is updated as part of this procedure, but it is not persisted.
    """
    from .models import PublishingError

    settings = get_current_registry().settings
    publishing_url = settings['publishing.url']
    headers = {
        'x-api-key': settings['publishing.api_key'],
        'content-type': 'application/json',
        }
    url = urlparse.urljoin(publishing_url,
                           '/contents/{}/roles'.format(model.id))

    # Acquire a list of known roles from publishing.
    response = requests.get(url)
    upstream_roles = response.json()

    # Compare upstream and mark entities for update.
    tobe_updated = set([])
    for role_entity in upstream_roles:
        uid = role_entity['uid']
        type_ = PUBLISHING_ROLES_MAPPING[role_entity['role']]
        has_accepted = role_entity['has_accepted']
        # Note, a role cannot be added or accepted through publishing.
        #   This content will become out-of-sync if content is managed,
        #   by another system other than authoring.
        try:
            role, index = [(r, i,)
                           for i, r in enumerate(model.metadata[type_])
                           if r['id'] == uid][0]
        except IndexError:
            # Doesn't exist locally... Out of sync!
            raise  # TODO
        # FIXME 'has_accepted' isn't worked into authoring yet,
        #       but this will need adjusted to role['has_accepted']
        if has_accepted != role.get('has_accepted'):
            # Mark the role for update.
            tobe_updated.add((uid, type_, role.get('has_accepted'),))

    # Look for roles that have not yet been pushed upstream.
    local_roles = []
    for role_type in PUBLISHING_ROLES_MAPPING.values():
        # FIXME 'has_accepted' isn't worked into authoring yet,
        #       but this will need adjusted to r['has_accepted']
        local_roles.extend([(r['id'], role_type, r.get('has_accepted'),)
                            for r in model.metadata[role_type]])
    for new_role in set(upstream_roles).symmetric_difference(set(local_roles)):
        tobe_updated.add(new_role)

    # Project and/or accept roles into publishing.
    _roles_mapping = {v: k for k, v in PUBLISHING_ROLES_MAPPING.items()}
    role_submission_keys = ('uid', 'role', 'has_accepted',)
    payload = [dict(zip(role_submission_keys,
                        (r[0], _roles_mapping[r[1]], r[2],)))
               for r in tobe_updated]
    response = requests.post(url, data=json.dumps(payload),
                             headers=headers)
    if response.status_code != 202:
        raise PublishingError(response)


def declare_licensors(model):
    """Declare license acceptance information on the model.
    The model is updated as part of this procedure, but it is not persisted.
    """
    from .models import PublishingError

    settings = get_current_registry().settings
    publishing_url = settings['publishing.url']
    headers = {
        'x-api-key': settings['publishing.api_key'],
        'content-type': 'application/json',
        }
    url = urlparse.urljoin(publishing_url,
                           '/contents/{}/licensors'.format(model.id))

    # Acquire a list of known roles from publishing.
    response = requests.get(url)
    upstream_license_info = response.json()
    upstream = upstream_license_info.get('licensors', [])

    # Compare upstream and mark entities for update.
    tobe_updated = set([])
    for entity in upstream:
        uid = entity['uid']
        has_accepted = entity['has_accepted']
        # Note, a licensor cannot be added or accepted through publishing.
        #   This content will become out-of-sync if content is managed,
        #   by another system other than authoring.
        try:
            _, index = [(rec, i,)
                           for i, rec in enumerate(model.licensor_acceptance)
                           if rec['id'] == uid][0]
        except IndexError:
            # Doesn't exist locally... Out of sync!
            raise  # TODO
        if has_accepted != entity['has_accepted']:
            # Mark the role for update.
            tobe_updated.add((uid, entity['has_accepted'],))

    # Look for licensors that have not yet been pushed upstream.
    # FIXME 'has_accepted' isn't worked into authoring yet,
    #       but this will need adjusted to r['has_accepted']
    local = [(r['id'], r.get('has_accepted'),)
             for r in model.licensor_acceptance]
    for new_licensor in set(upstream).symmetric_difference(set(local)):
        tobe_updated.add(new_licensor)

    # Project and/or accept licensors into publishing.
    submission_keys = ('uid', 'has_accepted',)
    payload = {
        'license_url': model.metadata['license'].url,
        'licensors': [dict(zip(submission_keys, x))
                      for x in tobe_updated],
        }
    response = requests.post(url, data=json.dumps(payload),
                             headers=headers)
    if response.status_code != 202:
        raise PublishingError(response)
