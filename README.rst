============
ckanext-adfs
============

**As of 2018-12-11 this extension has been tested against CKAN 2.8.1. However
YMMV.**
**The changes made to make it compatible for 2.8.1 are breaking changes for
earlier versions.**

A CKAN extension for validating users against Microsoft's Active Directory
Federated Services (ADFS) Single Sign On (SSO) API.

In layman's terms it lets you log in using some third-party source of
authentication provided by Microsoft and beloved by BDOs (Big Dumb Orgs).


------------
What is ADFS?
------------

Microsoft's Azure cloud-based offering provides Active Directory Federated
Services (ADFS for short). As far as we can tell these have absolutely nothing
to do with the "traditional" LDAP/ActiveDirectory we love to loath but is a
confusion thought up by their marketing department. In essence it is possible
to create an "Active Directory" within Azure to define groups of users. ADFS
is a way to allow such users to log in to some third party application (in this
case it's your instance of CKAN) via said Azure active directory. For this to
happen you'll need to create a new "application" (representing your CKAN
instance) within the relevant Azure active directory. Microsoft have good
documentation online for doing this (although see the caveat about UI changes
below).

If you merely want to test this extension you can take out a free trial at the
Azure website (although you'll need to provide credit card details to prove
you're not a bot).


------------
Requirements
------------

See the requirements.txt file for third party modules needed for this to
work (lxml and M2Crypto).

You'll also need the following packages installed::

    sudo apt-get install libxml2 libxml2-dev libxslt1.1 libxslt1-dev openssl libssl-dev swig python-dev


------------
Installation
------------

To install ckanext-adfs for development (or prod), activate your CKAN virtualenv and
do::

    git clone https://github.com/boykoc/ckanext-adfs.git
    cd ckanext-adfs
    python setup.py develop
    pip install -r requirements.txt

Add ``adfs`` to the ``ckan.plugins`` setting in your CKAN config file (by default the config file is located at
``/etc/ckan/default/production.ini``).

------------
Configururation
------------

In Azure ensure the following settings are correct for your application:

* Sign-on URL - should be https://yourdomain.com/user/login (replacing <yourdomain> with, er, your domain).
* Reply URL - should be https://yourdomain.com/adfs/signin/ (make sure you include the trailing slash).

On the machine hosting your instance of CKAN:

Ensure all the requirements are installed (see `requirements.txt` for further
details).

In your CKAN's production.ini / development.ini file you need to provide two settings in the
`[app:main]` section:

* adfs_wtrealm - the `APP ID URI` setting found in the "Get Started" / "Enable Users to Sign On" section on the "home" page for the application integrating with ADFS on the Azure website. This is usually the same as the APP ID URI you define in the settings for the application.
* adfs_metadata_url - a URL pointing to a remote file called `FederationMetadata.xml` containing the ADFS_NAMESPACE and adfs_x509 related values. This URL is in the "Federation Metadata Document URL" value in the "Enable Users to Sign On" section of the Azure website (at current time of writing).
* adfs_create_user = Optional Boolean, defaults to False. False requires a sysadmin to create the user via api or paster command first matching their email and user name to their organization email and username.
* adfs_organization_name = Name of Organization/Company (defaults to our organization)

* adfs_contact_email = Optional String (e.g. opendata@organization.com), defaults to 'your administrator'

* adfs_url_template - a template snippet for the URL that points to the ADFS authentication endpoint (e.g. {}idpinitiatedsignon.aspx?loginToRp={}). This template uses the wsfed endpoint extracted from FederationMetadata.xml and adfs_wtrealm.

*A WORD OF WARNING* Microsoft appears to change its UI in the Azure website
quite often so you may need to poke around to find the correct settings. It has
been our experience that their otherwise excellent documentation doesn't
always stay up-to-date and/or Google doesn't point to the most current version
of the documentation. YMMV.


------------
Development Environment:
------------

Create a new virtualenv and install the requirements with the `pip` command::

    $ mkvirtualenv foo
    (foo)$ pip install -r requirements.txt

Alternatively, make sure you've installed the requirements in CKAN's own
virtualenv.

To run the test suite type::

    $ python -m unittest discover

All the heavy lifting for checking the response is done in the `validation`
module.
