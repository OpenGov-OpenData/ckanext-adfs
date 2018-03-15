# encoding: utf-8

import logging
import ckan.lib.helpers as h
import ckan.model as model
import ckan.plugins.toolkit as toolkit
import pylons
import uuid
import base64
from validation import validate_saml
from metadata import get_certificates, get_federation_metadata, get_wsfed
from extract import get_user_info


log = logging.getLogger(__name__)


class ADFSRedirectController(toolkit.BaseController):
    """
    A custom home controller for receiving ADFS authorization responses.
    """

    def login(self):
        """
        Handle eggsmell request from the ADFS redirect_uri.
        """
        try:
            eggsmell = pylons.request.POST.get('wresult')
            if not eggsmell:
                request_data = dict(pylons.request.POST)
                eggsmell = base64.decodestring(request_data['SAMLResponse'])
        except:
            log.info('ADFS eggsmell')
            log.info(dict(pylons.request.POST))
        # We grab the metadata for each login because due to opaque
        # bureaucracy and lack of communication the certificates can be
        # changed. We looked into this and took made the call based upon lack
        # of user problems and tech being under our control vs the (small
        # amount of) latency from a network call per login attempt.
        metadata = get_federation_metadata(pylons.config['adfs_metadata_url'])
        x509_certificates = get_certificates(metadata)
        if not validate_saml(eggsmell, x509_certificates):
            raise ValueError('Invalid signature')
        username, email, firstname, surname = get_user_info(eggsmell)

        if not email:
            log.error('Unable to login with ADFS')
            log.error(eggsmell)
            raise ValueError('No email returned with ADFS')

        user = model.User.by_name(username)
        if user:
            if user.get('state') == 'deleted':
                # Deleted user
                log.error('Unable to login with ADFS, {} was deleted'.format(username))
                h.flash_error('This CKAN account was deleted and is no longer accessible.')
                toolkit.redirect_to(controller='user', action='login')
            else:
                # Existing user
                log.info('Logging in from ADFS with user: {}'.format(username))
        else:
            # New user, so create a record for them.
            log.info('Creating user from ADFS, username: {}'.format(username))
            user = model.User(name=username)
            user.sysadmin = False

        # Update fullname
        if firstname and surname:
            user.fullname = firstname + ' ' + surname
        # Update mail
        if email:
            user.email = email

        # Save the user in the database
        model.Session.add(user)
        model.Session.commit()
        model.Session.remove()

        pylons.session['adfs-user'] = username
        pylons.session['adfs-email'] = email
        pylons.session.save()

        toolkit.redirect_to(controller='user', action='dashboard', id=email)
        return
