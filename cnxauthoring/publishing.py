# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2014, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

import requests
from pyramid import httpexceptions

from . import utils
from .storage import storage


__all__ = ('post_to_publishing',)


def post_to_publishing(request, userid, submitlog, content_ids):
    """all params come from publish post. Content_ids is a json list of lists,
    containing ids of binders and the pages in them to be published.  Each binder
    is a list, starting with the binderid, and following with documentid of each
    draft page to publish. As a degenerate case, it may be a single list of this
    format. In addition to binder lists, the top level list may contain document
    ids - these will be published as a 'looseleaf' set of pages."""
    publishing_url = request.registry.settings['publishing.url']
    publishing_url = urlparse.urljoin(publishing_url, 'publications')
    filename = 'contents.epub'
    contents = []
    for content_id_item in content_ids:
        if type(content_id_item) == list: # binder list
            content = []
            for content_id in content_id_item:
                if content_id.endswith('@draft'):
                    content_id = content_id[:-len('@draft')]
                content_item = storage.get(id=content_id, submitter=userid)
                if content_item is None:
                    raise httpexceptions.HTTPBadRequest('Unable to publish: '
                            'content not found {}'.format(content_id))
                if not request.has_permission('publish', content):
                    raise httpexceptions.HTTPForbidden(
                        'You do not have permission to publish {}'.format(content_id))
                content.append(content_item)

        else:  #documentid
            content_id = content_id_item
            if content_id.endswith('@draft'):
                content_id = content_id[:-len('@draft')]
            content = storage.get(id=content_id)
            if content is None:
                raise httpexceptions.HTTPBadRequest('Unable to publish: '
                        'content not found {}'.format(content_id))
            if not request.has_permission('publish', content):
                raise httpexceptions.HTTPForbidden(
                    'You do not have permission to publish {}'.format(content_id))

        contents.append(content)

    upload_data = utils.build_epub(contents, userid, submitlog)
    files = {
        'epub': (filename, upload_data.read(), 'application/epub+zip'),
        }
    api_key = request.registry.settings['publishing.api_key']
    headers = {'x-api-key': api_key}
    return contents, requests.post(publishing_url, files=files, headers=headers)
