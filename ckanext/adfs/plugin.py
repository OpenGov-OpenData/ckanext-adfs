"""
Plugin for our ADFS
"""
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.logic.schema
import pylons
from ckanext.adfs import schema
from metadata import get_federation_metadata, get_wsfed
try:
    from ckan.common import config
except ImportError:
    from pylons import config


# Some awful XML munging.
WSFED_ENDPOINT = ''
WTREALM = config['adfs_wtrealm']
METADATA = get_federation_metadata(config['adfs_metadata_url'])
WSFED_ENDPOINT = get_wsfed(METADATA)
AUTH_URL_TEMPLATE = config.get('adfs_url_template','{}?wa=wsignin1.0&wreq=xml&wtrealm={}')


if not (WSFED_ENDPOINT):
    raise ValueError('Unable to read WSFED_ENDPOINT values for ADFS plugin.')


def adfs_authentication_endpoint():
    try:
        auth_endpoint = AUTH_URL_TEMPLATE.format(WSFED_ENDPOINT, WTREALM)
    except:
        auth_endpoint = '{}?wa=wsignin1.0&wreq=xml&wtrealm={}'.format(WSFED_ENDPOINT, WTREALM)
    return auth_endpoint


def is_adfs_user():
    return pylons.session.get('adfs-user')


class ADFSPlugin(plugins.SingletonPlugin):
    """
    Log us in via the ADFSes
    """
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IRoutes)
    plugins.implements(plugins.IAuthenticator)

    def update_config(self, config_):
        """
        Add our templates to CKAN's search path
        """
        ckan.logic.schema.user_new_form_schema = schema.user_new_form_schema
        ckan.logic.schema.user_edit_form_schema = schema.user_edit_form_schema
        ckan.logic.schema.default_update_user_schema = schema.default_update_user_schema
        toolkit.add_template_directory(config_, 'templates')

    def get_helpers(self):
        return dict(is_adfs_user=is_adfs_user,
                    adfs_authentication_endpoint=adfs_authentication_endpoint)

    def before_map(self, map):
        """
        Called before the routes map is generated. ``before_map`` is before any
        other mappings are created so can override all other mappings.

        :param map: Routes map object
        :returns: Modified version of the map object
        """
        # Route requests for our WAAD redirect URI to a custom controller
        map.connect(
            'adfs_redirect_uri', '/adfs/signin/',
            controller='ckanext.adfs.controller:ADFSRedirectController',
            action='login')
        # Route password reset requests to a custom controller
        map.connect(
            'adfs_request_reset', '/user/reset',
            controller='ckanext.adfs.controller:ADFSUserController',
            action='request_reset')
        return map

    def after_map(self, map):
        """
        Called after routes map is set up. ``after_map`` can be used to
        add fall-back handlers.

        :param map: Routes map object
        :returns: Modified version of the map object
        """
        return map

    def identify(self):
        """
        Called to identify the user.
        """
        user = pylons.session.get('adfs-user')
        if user:
            toolkit.c.user = user

    def login(self):
        """
        Called at login.
        """
        pass

    def logout(self):
        """
        Called at logout.
        """
        keys_to_delete = [key for key in pylons.session
                          if key.startswith('adfs')]
        if keys_to_delete:
            for key in keys_to_delete:
                del pylons.session[key]
            pylons.session.save()

    def abort(self, status_code, detail, headers, comment):
        """
        Called on abort.  This allows aborts due to authorization issues
        to be overriden.
        """
        return (status_code, detail, headers, comment)
