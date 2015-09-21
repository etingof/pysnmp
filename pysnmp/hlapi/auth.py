from pysnmp.entity import config
from pysnmp import error
from pyasn1.compat.octets import null

__all__ = ['CommunityData', 'UsmUserData',
           'usm3DESEDEPrivProtocol', 'usmAesCfb128Protocol',
           'usmAesCfb192Protocol', 'usmAesCfb256Protocol',
           'usmDESPrivProtocol', 'usmHMACMD5AuthProtocol',
           'usmHMACSHAAuthProtocol', 'usmNoAuthProtocol',
           'usmNoPrivProtocol']

class CommunityData:
    """Creates SNMP v1/v2c configuration entry.

    This object can be used by 
    :py:class:`~pysnmp.hlapi.asyncore.AsyncCommandGenerator` or
    :py:class:`~pysnmp.hlapi.asyncore.AsyncNotificationOriginator`
    and their derivatives for adding new entries to Local Configuration
    Datastore (LCD) managed by :py:class:`~pysnmp.hlapi.SnmpEngine`
    class instance.

    See :RFC:`2576#section-5.3` for more information on the 
    *SNMP-COMMUNITY-MIB::snmpCommunityTable*.

    Parameters
    ----------
    communityIndex : str
        Unique index value of a row in snmpCommunityTable. If it is the
        only positional parameter, it is taken as *communityName*.
    communityName : str
        SNMP v1/v2c community string.
    mpModel : int
        SNMP version - 0 for SNMPv1 and 1 for SNMPv2c.
    contextEngineId : str
        Indicates the location of the context in which management
        information is accessed when using the community string
        specified by the above communityName.
    contextName : str
        The context in which management information is accessed when
        using the above communityName.
    tag : str 
        Arbitrary string that specifies a set of transport endpoints
        to which a notification may be sent using communityName above
        (see also :RFC:`3413#section-4.1.4`).

    Examples
    --------
    >>> from pysnmp.hlapi import CommunityData
    >>> CommunityData('public')
    CommunityData(communityIndex='s1410706889', communityName=<COMMUNITY>, mpModel=1, contextEngineId=None, contextName='', tag='')
    >>> CommunityData('public', 'public')
    CommunityData(communityIndex='public', communityName=<COMMUNITY>, mpModel=1, contextEngineId=None, contextName='', tag='')
    >>>

    """
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

#: No Authentication Protocol.
usmNoAuthProtocol = config.usmNoAuthProtocol
#: The HMAC-MD5-96 Digest Authentication Protocol (:RFC:`3414#section-6`)
usmHMACMD5AuthProtocol = config.usmHMACMD5AuthProtocol
#: The HMAC-SHA-96 Digest Authentication Protocol (:RFC:`3414#section-7`) 
usmHMACSHAAuthProtocol = config.usmHMACSHAAuthProtocol

#: No Privacy Protocol.
usmNoPrivProtocol = config.usmNoPrivProtocol
#: The CBC-DES Symmetric Encryption Protocol (:RFC:`3414#section-8`)
usmDESPrivProtocol = config.usmDESPrivProtocol
#: The 3DES-EDE Symmetric Encryption Protocol (`draft-reeder-snmpv3-usm-3desede-00 <https://tools.ietf.org/html/draft-reeder-snmpv3-usm-3desede-00#section-5>`_)
usm3DESEDEPrivProtocol = config.usm3DESEDEPrivProtocol
#: The CFB128-AES-128 Symmetric Encryption Protocol (:RFC:`3826#section-3`)
usmAesCfb128Protocol = config.usmAesCfb128Protocol
#: The CFB128-AES-192 Symmetric Encryption Protocol (`draft-blumenthal-aes-usm-04 <https://tools.ietf.org/html/draft-blumenthal-aes-usm-04#section-3>`_)
usmAesCfb192Protocol = config.usmAesCfb192Protocol
#: The CFB128-AES-256 Symmetric Encryption Protocol (`draft-blumenthal-aes-usm-04 <https://tools.ietf.org/html/draft-blumenthal-aes-usm-04#section-3>`_)
usmAesCfb256Protocol = config.usmAesCfb256Protocol

class UsmUserData:
    """Creates SNMP v3 User Security Model (USM) configuration entry.

    This object can be used by 
    :py:class:`~pysnmp.hlapi.asyncore.AsyncCommandGenerator` or
    :py:class:`~pysnmp.hlapi.asyncore.AsyncNotificationOriginator`
    and their derivatives for adding new entries to Local Configuration
    Datastore (LCD) managed by :py:class:`~pysnmp.hlapi.SnmpEngine`
    class instance.

    See :RFC:`3414#section-5` for more information on the 
    *SNMP-USER-BASED-SM-MIB::usmUserTable*.

    Parameters
    ----------
    userName : str
        A human readable string representing the name of the SNMP USM user.
    authKey : str
        Initial value of the secret authentication key.  If not set,
        :py:class:`~pysnmp.hlapi.usmNoAuthProtocol`
        is implied.  If set and no *authProtocol* is specified,
        :py:class:`~pysnmp.hlapi.usmHMACMD5AuthProtocol`
        takes effect.
    privKey : str
        Initial value of the secret encryption key.  If not set,
        :py:class:`~pysnmp.hlapi.usmNoPrivProtocol`
        is implied.  If set and no *privProtocol* is specified,
        :py:class:`~pysnmp.hlapi.usmDESPrivProtocol`
        takes effect.
    authProtocol : tuple
        An indication of whether messages sent on behalf of this USM user
        can be authenticated, and if so, the type of authentication protocol
        which is used.

        Supported authentication protocol identifiers are:

        * :py:class:`~pysnmp.hlapi.usmNoAuthProtocol` (default is *authKey* not given)
        * :py:class:`~pysnmp.hlapi.usmHMACMD5AuthProtocol` (default if *authKey* is given)
        * :py:class:`~pysnmp.hlapi.usmHMACSHAAuthProtocol`
    privProtocol : tuple
        An indication of whether messages sent on behalf of this USM user 
        be encrypted, and if so, the type of encryption protocol which is used.

        Supported encryption protocol identifiers are:

        * :py:class:`~pysnmp.hlapi.usmNoPrivProtocol` (default is *authKey* not given)
        * :py:class:`~pysnmp.hlapi.usmDESPrivProtocol` (default if *authKey* is given)
        * :py:class:`~pysnmp.hlapi.usm3DESEDEPrivProtocol`
        * :py:class:`~pysnmp.hlapi.usmAesCfb128Protocol`
        * :py:class:`~pysnmp.hlapi.usmAesCfb192Protocol`
        * :py:class:`~pysnmp.hlapi.usmAesCfb256Protocol`

    Examples
    --------
    >>> from pysnmp.hlapi import UsmUserData
    >>> UsmUserData('testuser', authKey='authenticationkey')
    UsmUserData(userName='testuser', authKey=<AUTHKEY>, privKey=<PRIVKEY>, authProtocol=(1,3,6,1,6,3,10,1,1,2), privProtocol=(1,3,6,1,6,3,10,1,2,1))
    >>> UsmUserData('testuser', authKey='authenticationkey', privKey='encryptionkey')
    UsmUserData(userName='testuser', authKey=<AUTHKEY>, privKey=<PRIVKEY>, authProtocol=(1,3,6,1,6,3,10,1,1,2), privProtocol=(1,3,6,1,6,3,10,1,2,2))
    >>>

    """
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
