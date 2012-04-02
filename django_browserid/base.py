import logging
from warnings import warn
try:
    import json
except ImportError:
    import simplejson as json  # NOQA


from django.conf import settings

from browserid import LocalVerifier, RemoteVerifier

log = logging.getLogger(__name__)


DEFAULT_HTTP_TIMEOUT = 5
OKAY_RESPONSE = 'okay'
DEFAULT_VERIFIER = 'remote'
DEFAULT_AUDIENCES = ('*', )
AVAILABLE_VERIFIERS = ('remote', 'local', 'custom')


def get_audience(request):
    """Uses Django settings to format the audience.

    To use this function, make sure there is either a SITE_URL in
    your settings.py file or PROTOCOL and DOMAIN.

    Examples using SITE_URL:
        SITE_URL = 'http://127.0.0.1:8001'
        SITE_URL = 'https://example.com'
        SITE_URL = 'http://example.com'

    If you don't have a SITE_URL you can also use these varables:
    PROTOCOL, DOMAIN, and (optionally) PORT.
    Example 1:
        PROTOCOL = 'https://'
        DOMAIN = 'example.com'

    Example 2:
        PROTOCOL = 'http://'
        DOMAIN = '127.0.0.1'
        PORT = '8001'

    If none are set, we trust the request to populate the audience.
    This is *not secure*!
    """
    site_url = getattr(settings, 'SITE_URL', False)

    # Note audience based on request for developer warnings
    if request.is_secure():
        req_proto = 'https://'
    else:
        req_proto = 'http://'
    req_domain = request.get_host()

    # If we don't define it explicitly
    if not site_url:
        warn('Using DOMAIN and PROTOCOL to specify your BrowserID audience is '
             'deprecated. Please use the SITE_URL setting instead.',
             DeprecationWarning)

        # DOMAIN is example.com req_domain is example.com:8001
        domain = getattr(settings, 'DOMAIN', req_domain.split(':')[0])
        protocol = getattr(settings, 'PROTOCOL', req_proto)

        standards = {'https://': 443, 'http://': 80}
        if ':' in req_domain:
            req_port = req_domain.split(':')[1]
        else:
            req_port = None
        port = getattr(settings, 'PORT', req_port or standards[protocol])
        if port == standards[protocol]:
            site_url = ''.join(map(str, (protocol, domain)))
        else:
            site_url = ''.join(map(str, (protocol, domain, ':', port)))

    req_url = "%s%s" % (req_proto, req_domain)
    if site_url != "%s%s" % (req_proto, req_domain):
        log.warning('Misconfigured SITE_URL? settings has [%s], but '
                    'actual request was [%s] BrowserID may fail on '
                    'audience' % (site_url, req_url))
    return site_url


def get_verifier():
    """Uses the settings to return an appropriate verifier instance"""
    verifier_type = getattr(settings, 'BROWSERID_VERIFIER', DEFAULT_VERIFIER)

    if verifier_type not in AVAILABLE_VERIFIERS:
        raise ValueError('BROWSERID_VERIFIER should be %s' % \
                         ' or '.join(AVAILABLE_VERIFIERS))

    kwargs = {}
    kwargs['audiences'] = getattr(settings, 'BROWSERID_AUDIENCES',
                                  DEFAULT_AUDIENCES)

    log.debug("Audiences: %s" % kwargs['audiences'])

    if verifier_type == 'local':
        verifier = LocalVerifier(**kwargs)

    elif verifier_type == 'remote':
        # init the parameters
        verify_url = getattr(settings, 'BROWSERID_VERIFICATION_URL', None)
        trusted_secondaries = getattr(settings,
                                      'BROWSERID_TRUSTED_SECONDARIES', None)

        kwargs['verifier_url'] = verify_url
        kwargs['trusted_secondaries'] = trusted_secondaries
        kwargs['warning'] = False  # We don't want to yell each time

        if verify_url:
            log.debug("Verification URL: %s" % verify_url)
        if trusted_secondaries:
            log.debug("Trusted secondaries: %s" % trusted_secondaries)

        verifier = RemoteVerifier(**kwargs)

    elif verifier_type == 'custom':
        # the the verifier should already be set in the settings. The lookup
        # will fail if the setting is not set.
        verifier = settings.BROWSERID_VERIFIER_INSTANCE

    return verifier


def verify(assertion, audience):
    """Verify an assertion using PyBrowserID"""
    return get_verifier().verify(assertion, audience)
