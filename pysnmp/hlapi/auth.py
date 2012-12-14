from pysnmp.entity import config
from pyasn1.compat.octets import null

class CommunityData:
    mpModel = 1 # Default is SMIv2
    securityModel = mpModel + 1
    securityLevel = 'noAuthNoPriv'
    contextName = null
    tag = null
    def __init__(self, securityName, communityName=None, mpModel=None,
                 contextEngineId=None, contextName=None, tag=None):
        self.securityName = securityName
        self.communityName = communityName
        if mpModel is not None:
            self.mpModel = mpModel
            self.securityModel = mpModel + 1
        self.contextEngineId = contextEngineId
        if contextName is not None:
            self.contextName = contextName
        if tag is not None:
            self.tag = tag
        # Autogenerate securityName if not specified
        if communityName is None:
            self.communityName = securityName
            self.securityName = 's%s' % hash(
                ( securityName, self.mpModel,
                  self.contextEngineId, self.contextName, self.tag )
                )
            
    def __repr__(self):
        return '%s("%s", <COMMUNITY>, %r, %r, %r, %r)' % (
            self.__class__.__name__,
            self.securityName,
            self.mpModel,
            self.contextEngineId,
            self.contextName,
            self.tag
        )

class UsmUserData:
    authKey = privKey = None
    authProtocol = config.usmNoAuthProtocol
    privProtocol = config.usmNoPrivProtocol
    securityLevel = 'noAuthNoPriv'
    securityModel = 3
    mpModel = 3
    contextName = null
    # the contextEngineId/contextName values stored here should
    # be used for USM configuration only, not for PDU contents
    def __init__(self, securityName,
                 authKey=None, privKey=None,
                 authProtocol=None, privProtocol=None,
                 contextEngineId=None, contextName=None):
        self.securityName = securityName
        
        if authKey is not None:
            self.authKey = authKey
            if authProtocol is None:
                self.authProtocol = config.usmHMACMD5AuthProtocol
            else:
                self.authProtocol = authProtocol
            if self.securityLevel != 'authPriv':
                self.securityLevel = 'authNoPriv'

        if privKey is not None:
            self.privKey = privKey
            if self.authProtocol == config.usmNoAuthProtocol:
                raise error.PySnmpError('Privacy implies authenticity')
            self.securityLevel = 'authPriv'
            if privProtocol is None:
                self.privProtocol = config.usmDESPrivProtocol
            else:
                self.privProtocol = privProtocol

        self.contextEngineId = contextEngineId
        if contextName is not None:
            self.contextName = contextName
        
    def __repr__(self):
        return '%s("%s", <AUTHKEY>, <PRIVKEY>, %r, %r, %r, %r)' % (
            self.__class__.__name__,
            self.securityName,
            self.authProtocol,
            self.privProtocol,
            self.contextEngineId,
            self.contextName
        )
