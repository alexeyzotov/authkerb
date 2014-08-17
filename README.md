authkerb
========

Kerberos authentication for Twisted

```python
import os
import sys

from twisted.cred.portal import IRealm, Portal
from twisted.internet import reactor
from twisted.python import log
from twisted.web import server
from twisted.web.guard import HTTPAuthSessionWrapper, BasicCredentialFactory
from twisted.web.resource import IResource, Resource

from zope.interface import implements

import authkerb


class Simple(Resource):
    isLeaf = True
    
    def render_GET(self, request):
        return '<html>Hello, world!</html>'


class Realm(object):
    implements(IRealm)
    
    def requestAvatar(self, avatarId, mind, *interfaces):
        if IResource in interfaces:
            return (IResource, Simple(), lambda: None)
        
        raise NotImplementedError()


os.environ['KRB5_KTNAME'] = '/path/to/keytab'
log.startLogging(sys.stdout)

negotiateChecker = authkerb.NegotiateCredentialsChecker()
basicChecker = authkerb.BasicCredentialsChecker('HTTP/example.org', 'EXAMPLE.ORG')

portal = Portal(Realm(), [negotiateChecker, basicChecker])

negotiateFactory = authkerb.NegotiateCredentialFactory('HTTP')
basicFactory = BasicCredentialFactory('realm')

resource = HTTPAuthSessionWrapper(portal, [negotiateFactory, basicFactory])
site = server.Site(resource)

reactor.listenTCP(8080, site)
reactor.run()
```
