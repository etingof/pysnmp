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
        # a single arg is considered as a community name
        if communityName is None:
            communityName, communityIndex = communityIndex, None
        self.communityName = communityName
        # Autogenerate communityIndex if not specified
        if communityIndex is None:
            self.communityIndex = self.securityName = 's%s' % hash(
                ( self.communityName,
                  self.mpModel,
                  self.contextEngineId,
                  self.contextName,
                  self.tag )
            )
        else:
            self.communityIndex = communityIndex
            self.securityName = securityName is not None and securityName or communityIndex

    def __hash__(self):
        raise TypeError('%s is not hashable' % self.__class__.__name__)

    def __repr__(self):
        return '%s(communityIndex=%r, communityName=<COMMUNITY>, mpModel=%r, contextEngineId=%r, contextName=%r, tag=%r, securityName=%r)' % (
            self.__class__.__name__,
            self.communityIndex,
            self.mpModel,
            self.contextEngineId,
            self.contextName,
            self.tag,
            self.securityName
        )

    def clone(self, communityIndex=None, communityName=None,
              mpModel=None, contextEngineId=None,
              contextName=None, tag=None, securityName=None):
        # a single arg is considered as a community name
        if communityName is None:
            communityName, communityIndex = communityIndex, None
        return self.__class__(
            communityIndex,
            communityName is None and self.communityName or communityName,
            mpModel is None and self.mpModel or mpModel,
            contextEngineId is None and self.contextEngineId or contextEngineId,
            contextName is None and self.contextName or contextName,
            tag is None and self.tag or tag,
            securityName is None and self.securityName or securityName
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
        return '%s(userName=%r, authKey=<AUTHKEY>, privKey=<PRIVKEY>, authProtocol=%r, privProtocol=%r, securityEngineId=%r, securityName=%r)'%(
            self.__class__.__name__,
            self.userName,
            self.authProtocol,
            self.privProtocol,
            self.securityEngineId is None and '<DEFAULT>' or self.securityEngineId,
            self.securityName
        )

    def clone(self, userName=None,
              authKey=None, privKey=None,
              authProtocol=None, privProtocol=None,
              securityEngineId=None, securityName=None):
        return self.__class__(
            userName is None and self.userName or userName,
            authKey is None and self.authKey or authKey,
            privKey is None and self.privKey or privKey,
            authProtocol is None and self.authProtocol or authProtocol,
            privProtocol is None and self.privProtocol or privProtocol,
            securityEngineId is None and self.securityEngineId or securityEngineId,
            securityName=securityName is None and self.securityName or securityName
        )
