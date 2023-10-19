"""
Plugin for our ADFS
"""
import logging
import base64
import uuid
import ckan.lib.mailer as mailer
import ckan.lib.navl.dictization_functions as dict_fns
import ckan.logic as logic
import ckan.model as model
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

from ckanext.adfs.validation import validate_saml
from ckanext.adfs.metadata import get_certificates, get_federation_metadata, get_wsfed
from ckanext.adfs.extract import get_user_info
from ckanext.adfs import schema as adfs_schema
from ckan.logic import schema as core_schema
from ckan.common import session, request
from flask import Blueprint

log = logging.getLogger(__name__)


# Some awful XML munging.
WSFED_ENDPOINT = ''
WTREALM = toolkit.config['adfs_wtrealm']
METADATA = get_federation_metadata(toolkit.config['adfs_metadata_url'])
WSFED_ENDPOINT = get_wsfed(METADATA)
AUTH_URL_TEMPLATE = toolkit.config.get('adfs_url_template', '{}?wa=wsignin1.0&wreq=xml&wtrealm={}')


if not (WSFED_ENDPOINT):
    raise ValueError('Unable to read WSFED_ENDPOINT values for ADFS plugin.')


def adfs_organization_name():
    return toolkit.config.get('adfs_organization_name', 'our organization')


def adfs_authentication_endpoint():
    try:
        auth_endpoint = AUTH_URL_TEMPLATE.format(WSFED_ENDPOINT, WTREALM)
    except:
        auth_endpoint = '{}?wa=wsignin1.0&wreq=xml&wtrealm={}'.format(WSFED_ENDPOINT, WTREALM)
    return auth_endpoint


def is_adfs_user():
    return session.get('adfs-user')


def make_password():
    """Create a hard to guess password."""
    out = ''
    for n in range(8):
        out += str(uuid.uuid4())
    return out


def _parse_form_data(request):
    return logic.clean_dict(
        dict_fns.unflatten(
            logic.tuplize_dict(
                logic.parse_params(request.form)
            )
        )
    )


def login():
    """
    A custom home controller for receiving ADFS authorization responses.
    """

    """
    Handle eggsmell request from the ADFS redirect_uri.
    """
    try:
        eggsmell = toolkit.request.form['wresult']
        if not eggsmell:
            request_data = _parse_form_data(toolkit.request)
            eggsmell = base64.decodebytes(request_data['SAMLResponse'])
    except Exception as ex:
        log.error('Missing eggsmell. `wresult` param does not exist.')
        log.exception(ex)
        toolkit.h.flash_error('Not able to successfully authenticate.')
        return toolkit.redirect_to('/user/login')

    # We grab the metadata for each login because due to opaque
    # bureaucracy and lack of communication the certificates can be
    # changed. We looked into this and took made the call based upon lack
    # of user problems and tech being under our control vs the (small
    # amount of) latency from a network call per login attempt.
    metadata = get_federation_metadata(toolkit.config['adfs_metadata_url'])
    x509_certificates = get_certificates(metadata)
    if not validate_saml(eggsmell, x509_certificates):
        raise ValueError('Invalid signature')
    username, email, firstname, surname = get_user_info(eggsmell)

    if not email:
        log.error('Unable to login with ADFS')
        log.error(eggsmell)
        raise ValueError('No email returned with ADFS')

    user = _get_user(username)
    if user:
        if not user.is_active():
            # Deleted user
            log.error('Unable to login with ADFS, {} was deleted'.format(username))
            toolkit.h.flash_error('This CKAN account was deleted and is no longer accessible.')
            toolkit.redirect_to(controller='user', action='login')
        else:
            # Existing user
            log.info('Logging in from ADFS with username: {}'.format(username))
    elif toolkit.config.get('adfs_create_user', False):
        # New user, so create a record for them if configuration allows.
        log.info('Creating user from ADFS, username: {}'.format(username))
        user = model.User(name=username)
        user.sysadmin = False

    # Update fullname
    if firstname and surname:
        user.fullname = firstname + ' ' + surname
    # Update mail
    if email:
        user.email = email

    user.password = make_password()

    # Save the user in the database
    model.Session.add(user)
    model.Session.commit()
    model.Session.remove()

    session['adfs-user'] = username
    session['adfs-email'] = email
    session.save()

    # Log the user in programatically.
    # Reference: ckan/views/user.py
    # By this point we either have a user or created one and they're good to login.
    resp = toolkit.h.redirect_to('user.logged_in')

    '''Set the repoze.who cookie to match a given user_id'''
    if 'repoze.who.plugins' in request.environ:
        rememberer = request.environ['repoze.who.plugins']['friendlyform']
        identity = {'repoze.who.userid': username}
        resp.headers.extend(rememberer.remember(request.environ, identity))

    return resp


def request_reset():
    context = {'model': model, 'session': model.Session, 'user': toolkit.c.user,
                'auth_user_obj': toolkit.c.userobj}
    data_dict = {'id': request.params.get('user')}
    try:
        toolkit.check_access('request_reset', context)
    except toolkit.NotAuthorized:
        toolkit.abort(403, toolkit._('Unauthorized to request reset password.'))

    if request.method == 'POST':
        id = request.params.get('user') or request.form.get('user')
        if id in (None, u''):
            toolkit.h.flash_error(toolkit._(u'Email is required'))
            return toolkit.h.redirect_to(u'/user/reset')
        context = {'model': model,
                    'user': toolkit.c.user,
                    u'ignore_auth': True}
        user_objs = []

        if u'@' not in id:
            try:
                user_dict = toolkit.get_action('user_show')(context, {'id': id})
                user_objs.append(context['user_obj'])
            except toolkit.ObjectNotFound:
                pass
        else:
            user_list = logic.get_action(u'user_list')(context, {
                u'email': id
            })
            if user_list:
                # send reset emails for *all* user accounts with this email
                # (otherwise we'd have to silently fail - we can't tell the
                # user, as that would reveal the existence of accounts with
                # this email address)
                for user_dict in user_list:
                    logic.get_action(u'user_show')(
                        context, {u'id': user_dict[u'id']})
                    user_objs.append(context[u'user_obj'])

        if not user_objs:
            log.info(u'User requested reset link for unknown user: {}'
                        .format(id))

        for user_obj in user_objs:
            # Don't reset password for ADFS users
            if user_obj.password is None or '@' in user_obj.name:
                # always tell the user it succeeded, because otherwise we reveal
                # which accounts are using ADFS
                toolkit.h.flash_success(
                    toolkit._(u'A reset link has been emailed to you '
                        '(unless the account specified does not exist)'))
                return toolkit.h.redirect_to(u'/')

            log.info(u'Emailing reset link to user: {}'
                        .format(user_obj.name))
            try:
                mailer.send_reset_link(user_obj)
            except mailer.MailerException as e:
                toolkit.h.flash_error(
                    toolkit._(u'Error sending the email. Try again later '
                        'or contact an administrator for help')
                )
                log.exception(e)
                return toolkit.h.redirect_to(u'/')
        # always tell the user it succeeded, because otherwise we reveal
        # which accounts exist or not
        toolkit.h.flash_success(
            toolkit._(u'A reset link has been emailed to you '
                '(unless the account specified does not exist)'))
        return toolkit.h.redirect_to(u'/')
    return toolkit.render('user/request_reset.html')


class ADFSPlugin(plugins.SingletonPlugin):
    """
    Log us in via the ADFSes
    """
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IAuthenticator)

    def update_config(self, config):
        """
        Add our templates to CKAN's search path
        """
        toolkit.add_template_directory(config, 'templates')

        # Monkeypatching user schemas in order to enforce a password policy
        core_schema.user_new_form_schema = adfs_schema.user_new_form_schema
        core_schema.user_edit_form_schema = adfs_schema.user_edit_form_schema
        core_schema.default_update_user_schema = adfs_schema.default_update_user_schema

    def get_helpers(self):
        return dict(is_adfs_user=is_adfs_user,
                    adfs_authentication_endpoint=adfs_authentication_endpoint,
                    adfs_organization_name=adfs_organization_name)

    def get_blueprint(self):
        blueprint = Blueprint('adfs_redirect_uri', self.__module__)
        rules = [
            ('/adfs/signin/', 'login', login),
            ('/user/reset', 'request_reset', request_reset)
        ]
        for rule in rules:
            blueprint.add_url_rule(*rule, methods=['POST'])

        return blueprint

    def identify(self):
        """
        Called to identify the user.
        """
        environ = toolkit.request.environ
        user = None
        if 'repoze.who.identity' in environ:
            user = environ['repoze.who.identity']['repoze.who.userid']
            # In CKAN 2.9.6 '{user_id},1' is stored in session cookie instead of username
            if toolkit.check_ckan_version(min_version='2.9.6', max_version='2.9.99') and user.endswith(',1'):
                user_id = user[:-2]
                user_obj = model.User.get(user_id)
                if user_obj:
                    user = user_obj.name
        toolkit.c.user = user

    def login(self):
        """
        Called at login.
        Nothing to do here. If default CKAN login, let CKAN do it's thing.
        If ADFS login, user is logged in above and this isn't called as we
        by-pass the login_handler setup by CKAN and repoze.who.
        """
        pass

    def logout(self):
        """
        Called at logout.
        """
        keys_to_delete = [key for key in session
                          if key.startswith('adfs')]
        if keys_to_delete:
            for key in keys_to_delete:
                del session[key]
            session.save()

    def abort(self, status_code, detail, headers, comment):
        """
        Called on abort.  This allows aborts due to authorization issues
        to be overridden.
        """
        return (status_code, detail, headers, comment)


def _get_user(name):
    """
    Return the CKAN user with the given user name, or None.
    Check state, state: deleted can still login but gets a blank page because
    CKAN is handling authorization later as well.
    """
    try:
        user = toolkit.get_action('user_show')(data_dict = {'id': name})
        if user['state'] == 'active':
            return user
        else:
            raise toolkit.ObjectNotFound
    except toolkit.ObjectNotFound:
        return None


class FileNotFoundException(Exception):
    pass