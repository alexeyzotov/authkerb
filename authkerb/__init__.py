import kerberos

from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import ICredentials, IUsernamePassword
from twisted.cred.error import LoginFailed, UnauthorizedLogin
from twisted.internet import defer
from twisted.internet.threads import deferToThread
from twisted.python import log
from twisted.web.iweb import ICredentialFactory

from zope.interface import implements


class BasicCredentialsChecker(object):
    implements(ICredentialsChecker)
    
    credentialInterfaces = (IUsernamePassword,)
    
    def __init__(self, service, default_realm, allow_anonymous=False):
        self.service = service
        self.default_realm = default_realm
        self.allow_anonymous = allow_anonymous
    
    def requestAvatarId(self, credentials):
        if not credentials.username:
            if self.allow_anonymous:
                return defer.succeed(credentials.username)
            
            return defer.fail(UnauthorizedLogin())
        
        return deferToThread(self.checkPassword, credentials)
    
    def checkPassword(self, credentials):
        try:
            res = kerberos.checkPassword(
                credentials.username,
                credentials.password,
                self.service,
                self.default_realm
            )
        except kerberos.KrbError as e:
            msg = repr(e)
            log.msg(msg)
            raise UnauthorizedLogin(msg)
        
        if not res:
            raise UnauthorizedLogin()
        
        username, sep, realm = credentials.username.rpartition('@')
        if sep != '@':
            return '%s@%s' % (credentials.username, self.default_realm)
        
        return credentials.username


class INegotiateCredentials(ICredentials):
    """
    We are negotiate credentials
    """


class NegotiateCredentials(object):
    implements(INegotiateCredentials)
    
    def __init__(self, principal):
        self.principal = principal


class ServerGSSContext(object):
    def __init__(self, serviceType=''):
        self.serviceType = serviceType
        self.context = None
    
    def __enter__(self):
        try:
            res, self.context = kerberos.authGSSServerInit(self.serviceType)
        except kerberos.KrbError as e:
            msg = repr(e)
            log.msg(msg)
            raise LoginFailed(msg)
        
        if res < 0:
            raise LoginFailed()
        
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        if self.context:
            try:
                kerberos.authGSSServerClean(self.context)
            except kerberos.KrbError as e:
                msg = repr(e)
                log.msg(msg)
                raise LoginFailed(msg)
        
        if exc_value:
            msg = repr(exc_value)
            log.msg(msg)
            raise LoginFailed(msg)
    
    def step(self, challenge):
        return kerberos.authGSSServerStep(self.context, challenge)
    
    def response(self):
        return kerberos.authGSSServerResponse(self.context)
    
    def userName(self):
        return kerberos.authGSSServerUserName(self.context)
    
    def targetName(self):
        return kerberos.authGSSServerTargetName(self.context)


class NegotiateCredentialFactory(object):
    implements(ICredentialFactory)
    
    scheme = 'negotiate'
    
    def __init__(self, serviceType=''):
        self.serviceType = serviceType
    
    def getChallenge(self, request):
        return {}
    
    def decode(self, challenge, request):
        with ServerGSSContext(self.serviceType) as context:
            res = context.step(challenge)
            if res < 0:
                raise LoginFailed()
            
            response = context.response()
            request.responseHeaders.addRawHeader(
                'www-authenticate',
                '%s %s' % (self.scheme, response)
            )
            
            if res == kerberos.AUTH_GSS_COMPLETE:
                principal = context.userName()
                return NegotiateCredentials(principal)
        
        raise LoginError()


class NegotiateCredentialsChecker(object):
    implements(ICredentialsChecker)
    
    credentialInterfaces = (INegotiateCredentials,)
    
    def requestAvatarId(self, credentials):
        return credentials.principal
