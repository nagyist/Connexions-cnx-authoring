# -*- coding: utf-8 -*-
# ###
# Copyright (c) 2014, Rice University
# This software is subject to the provisions of the GNU Affero General
# Public License version 3 (AGPLv3).
# See LICENCE.txt for details.
# ###
from openstax_accounts.interfaces import IOpenstaxAccountsAuthenticationPolicy
from pyramid.config import Configurator
from pyramid import security
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.session import SignedCookieSessionFactory
from pyramid_multiauth import MultiAuthenticationPolicy
from webob import Request, Response

from cnxpublishing.main import declare_routes

SETTINGS = {
    }


def make_app(global_config, **settings):
    """Application factory"""
    config = Configurator(settings=settings, root_factory=RootFactory)
    declare_routes(config)

    session_factory = SignedCookieSessionFactory(
        settings.get('session_key', 'itsaseekreet'))
    config.set_session_factory(session_factory)

    api_key_entities = _parse_api_key_lines(settings)
    api_key_authn_policy = APIKeyAuthenticationPolicy(api_key_entities)
    config.include('openstax_accounts.main')
    openstax_authn_policy = config.registry.getUtility(IOpenstaxAccountsAuthenticationPolicy)
    policies = [api_key_authn_policy, openstax_authn_policy]
    authn_policy = MultiAuthenticationPolicy(policies)
    config.set_authentication_policy(authn_policy)
    authz_policy = ACLAuthorizationPolicy()
    config.set_authorization_policy(authz_policy)


    return config.make_wsgi_app()
