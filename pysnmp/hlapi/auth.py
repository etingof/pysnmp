from pysnmp.entity import config
from pysnmp import error
from pyasn1.compat.octets import null

class CommunityData:
    mpModel = 1 # Default is SMIv2
    securityModel = mpModel + 1
    securityLevel = 'noAuthNoPriv'
    contextName = null
    tag = null
    def __init__(self, communityIndex, communityName=None, mpModel=None,
                 contextEngineId=None, contextName=None, tag=None,
                 securityName=None):
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
            self.communityName = communityIndex
            self.communityIndex = self.securityName = 's%s' % hash(
                ( communityIndex, self.mpModel,
                  self.contextEngineId, self.contextName, self.tag )
                )
        else:
            self.communityIndex = communityIndex
            self.communityName = communityName
            self.securityName = securityName is not None and securityName or communityIndex

    def __hash__(self):
        raise TypeError('%s is not hashable' % self.__class__.__name__)

    def __repr__(self):
        return '%s("%s", <COMMUNITY>, %r, %r, %r, %r, %r)' % (
            self.__class__.__name__,
            self.communityIndex,
            self.mpModel,
            self.contextEngineId,
            self.contextName,
            self.tag,
            self.securityName
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
    def __init__(self, userName,
                 authKey=None, privKey=None,
                 authProtocol=None, privProtocol=None,
                 securityEngineId=None,
                 # deprecated parameters begin
                 contextName=None,
                 contextEngineId=None,
                 # deprecated parameters end
                 securityName=None):
        self.userName = userName
        if securityName is None:
            self.securityName = userName
        else:
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

        # the contextEngineId parameter is actually a securityEngineId
        if securityEngineId is None:
            securityEngineId = contextEngineId
        self.contextEngineId = self.securityEngineId = securityEngineId

        # the contextName parameter should never be used here
        if contextName is not None:
            self.contextName = contextName
        
    def __hash__(self):
        raise TypeError('%s is not hashable' % self.__class__.__name__)

    def __repr__(self):
        return '%s("%s", <AUTHKEY>, <PRIVKEY>, %r, %r, %r, securityName=%r)'%(
            self.__class__.__name__,
            self.userName,
            self.authProtocol,
            self.privProtocol,
            self.securityEngineId,
            self.securityName
        )
