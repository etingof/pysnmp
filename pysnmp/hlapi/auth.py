#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pysnmp.entity import config
from pysnmp import error
from pyasn1.compat.octets import null

__all__ = ['CommunityData', 'UsmUserData',
           'usm3DESEDEPrivProtocol', 'usmAesCfb128Protocol',
           'usmAesCfb192Protocol', 'usmAesCfb256Protocol',
           'usmAesBlumenthalCfb192Protocol', 'usmAesBlumenthalCfb256Protocol',
           'usmDESPrivProtocol', 'usmHMACMD5AuthProtocol',
           'usmHMACSHAAuthProtocol', 'usmHMAC128SHA224AuthProtocol',
           'usmHMAC192SHA256AuthProtocol', 'usmHMAC256SHA384AuthProtocol',
           'usmHMAC384SHA512AuthProtocol', 'usmNoAuthProtocol',
           'usmNoPrivProtocol']


class CommunityData(object):
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
    communityIndex: :py:class:`str`, :py:class:`~pysnmp.proto.rfc1902.OctetString`
        Unique index value of a row in snmpCommunityTable. If it is the
        only positional parameter, it is treated as a *communityName*.

    communityName: :py:class:`str`, :py:class:`~pysnmp.proto.rfc1902.OctetString`
        SNMP v1/v2c community string.

    mpModel: :py:class:`int`
        SNMP message processing model AKA SNMP version. Known SNMP versions are:

        * `0` - for SNMP v1
        * `1` - for SNMP v2c (default)


    contextEngineId: :py:class:`str`, :py:class:`~pysnmp.proto.rfc1902.OctetString`
        Indicates the location of the context in which management
        information is accessed when using the community string
        specified by the above communityName.

    contextName: :py:class:`str`, :py:class:`~pysnmp.proto.rfc1902.OctetString`
        The context in which management information is accessed when
        using the above communityName.

    tag: :py:class:`str`
        Arbitrary string that specifies a set of transport endpoints
        from which a command responder application will accept
        management requests with given *communityName* or to which
        notification originator application will send notifications
        when targets are specified by a tag value(s).

        The other way to look at the *tag* feature is that it can make
        specific *communityName* only valid for certain targets.

        The other use-case is when multiple distinct SNMP peers share
        the same *communityName* -- binding each instance of
        *communityName* to transport endpoint lets you distinguish
        SNMP peers from each other (e.g. resolving *communityName* into
        proper *securityName*).

        For more technical information on SNMP configuration tags please
        refer to :RFC:`3413#section-4.1.1` and :RFC:`2576#section-5.3`
        (e.g. the *snmpCommunityTransportTag* object).

        See also: :py:class:`~pysnmp.hlapi.UdpTransportTarget`

    Warnings
    --------
    If the same *communityIndex* value is supplied repeatedly with
    different *communityName* (or other parameters), the later call
    supersedes all previous calls.

    Make sure not to configure duplicate *communityName* values unless
    they have distinct *mpModel* and/or *tag* fields. This will make
    *communityName* based database lookup ambiguous.

    Examples
    --------
    >>> from pysnmp.hlapi import CommunityData
    >>> CommunityData('public')
    CommunityData(communityIndex='s1410706889', communityName=<COMMUNITY>, mpModel=1, contextEngineId=None, contextName='', tag='')
    >>> CommunityData('public', 'public')
    CommunityData(communityIndex='public', communityName=<COMMUNITY>, mpModel=1, contextEngineId=None, contextName='', tag='')
    >>>

    """
    mpModel = 1  # Default is SMIv2
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
                (self.communityName, self.mpModel, self.contextEngineId,
                 self.contextName, self.tag)
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

usmNoAuthProtocol = config.usmNoAuthProtocol
"""No Authentication Protocol"""

usmHMACMD5AuthProtocol = config.usmHMACMD5AuthProtocol
"""The HMAC-MD5-96 Digest Authentication Protocol (:RFC:`3414#section-6`)"""

usmHMACSHAAuthProtocol = config.usmHMACSHAAuthProtocol
"""The HMAC-SHA-96 Digest Authentication Protocol AKA SHA-1 (:RFC:`3414#section-7`)"""

usmHMAC128SHA224AuthProtocol = config.usmHMAC128SHA224AuthProtocol
"""The HMAC-SHA-2 Digest Authentication Protocols (:RFC:`7860`)"""

usmHMAC192SHA256AuthProtocol = config.usmHMAC192SHA256AuthProtocol
"""The HMAC-SHA-2 Digest Authentication Protocols (:RFC:`7860`)"""

usmHMAC256SHA384AuthProtocol = config.usmHMAC256SHA384AuthProtocol
"""The HMAC-SHA-2 Digest Authentication Protocols (:RFC:`7860`)"""

usmHMAC384SHA512AuthProtocol = config.usmHMAC384SHA512AuthProtocol
"""The HMAC-SHA-2 Digest Authentication Protocols (:RFC:`7860`)"""

usmNoPrivProtocol = config.usmNoPrivProtocol
"""No Privacy Protocol"""

usmDESPrivProtocol = config.usmDESPrivProtocol
"""The CBC-DES Symmetric Encryption Protocol (:RFC:`3414#section-8`)"""

usm3DESEDEPrivProtocol = config.usm3DESEDEPrivProtocol
"""The 3DES-EDE Symmetric Encryption Protocol (`draft-reeder-snmpv3-usm-3desede-00 <https:://tools.ietf.org/html/draft-reeder-snmpv3-usm-3desede-00#section-5>`_)"""

usmAesCfb128Protocol = config.usmAesCfb128Protocol
"""The CFB128-AES-128 Symmetric Encryption Protocol (:RFC:`3826#section-3`)"""

usmAesCfb192Protocol = config.usmAesCfb192Protocol
"""The CFB128-AES-192 Symmetric Encryption Protocol (`draft-blumenthal-aes-usm-04 <https:://tools.ietf.org/html/draft-blumenthal-aes-usm-04#section-3>`_) with Reeder key localization"""

usmAesCfb256Protocol = config.usmAesCfb256Protocol
"""The CFB128-AES-256 Symmetric Encryption Protocol (`draft-blumenthal-aes-usm-04 <https:://tools.ietf.org/html/draft-blumenthal-aes-usm-04#section-3>`_) with Reeder key localization"""

usmAesBlumenthalCfb192Protocol = config.usmAesBlumenthalCfb192Protocol
"""The CFB128-AES-192 Symmetric Encryption Protocol (`draft-blumenthal-aes-usm-04 <https:://tools.ietf.org/html/draft-blumenthal-aes-usm-04#section-3>`_)"""

usmAesBlumenthalCfb256Protocol = config.usmAesBlumenthalCfb256Protocol
"""The CFB128-AES-256 Symmetric Encryption Protocol (`draft-blumenthal-aes-usm-04 <https:://tools.ietf.org/html/draft-blumenthal-aes-usm-04#section-3>`_)"""

usmKeyTypePassphrase = config.usmKeyTypePassphrase
"""USM key material type - plain-text pass phrase (:RFC:`3414#section-2.6`)"""

usmKeyTypeMaster = config.usmKeyTypeMaster
"""USM key material type - hashed pass-phrase AKA master key (:RFC:`3414#section-2.6`)"""

usmKeyTypeLocalized = config.usmKeyTypeLocalized
"""USM key material type - hashed pass-phrase hashed with Context SNMP Engine ID (:RFC:`3414#section-2.6`)"""


class UsmUserData(object):
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
    userName: :py:class:`str`, :py:class:`~pysnmp.proto.rfc1902.OctetString`
        A human readable string representing the name of the SNMP USM user.

    Other Parameters
    ----------------
    authKey: :py:class:`str`, :py:class:`~pysnmp.proto.rfc1902.OctetString`
        Initial value of the secret authentication key.  If not set,
        :py:class:`~pysnmp.hlapi.usmNoAuthProtocol`
        is implied.  If set and no *authProtocol* is specified,
        :py:class:`~pysnmp.hlapi.usmHMACMD5AuthProtocol`
        takes effect.

    privKey: :py:class:`str`, :py:class:`~pysnmp.proto.rfc1902.OctetString`
        Initial value of the secret encryption key.  If not set,
        :py:class:`~pysnmp.hlapi.usmNoPrivProtocol`
        is implied.  If set and no *privProtocol* is specified,
        :py:class:`~pysnmp.hlapi.usmDESPrivProtocol`
        takes effect.

    authProtocol: :py:class:`tuple`, :py:class:`~pysnmp.proto.rfc1902.ObjectIdentifier`
        An indication of whether messages sent on behalf of this USM user
        can be authenticated, and if so, the type of authentication protocol
        which is used.

        Supported authentication protocol identifiers are:

        * :py:class:`~pysnmp.hlapi.usmNoAuthProtocol` (default is *authKey* not given)
        * :py:class:`~pysnmp.hlapi.usmHMACMD5AuthProtocol` (default if *authKey* is given)
        * :py:class:`~pysnmp.hlapi.usmHMACSHAAuthProtocol`
        * :py:class:`~pysnmp.hlapi.usmHMAC128SHA224AuthProtocol`
        * :py:class:`~pysnmp.hlapi.usmHMAC192SHA256AuthProtocol`
        * :py:class:`~pysnmp.hlapi.usmHMAC256SHA384AuthProtocol`
        * :py:class:`~pysnmp.hlapi.usmHMAC384SHA512AuthProtocol`


    securityEngineId: :py:class:`~pysnmp.proto.rfc1902.OctetString`
        The snmpEngineID of the authoritative SNMP engine to which a
        dateRequest message is to be sent. Will be automatically
        discovered from peer if not given, unless localized keys
        are used. In the latter case *securityEngineId* must be
        specified.

        See :RFC:`3414#section-2.5.1` for technical explanation.

    securityName: :py:class:`str`, :py:class:`~pysnmp.proto.rfc1902.OctetString`
        Together with the snmpEngineID it identifies a row in the
        *SNMP-USER-BASED-SM-MIB::usmUserTable* that is to be used
        for securing the message.

        See :RFC:`3414#section-2.5.1` for technical explanation.

    privProtocol: :py:class:`tuple`, :py:class:`~pysnmp.proto.rfc1902.ObjectIdentifier`
        An indication of whether messages sent on behalf of this USM user
        be encrypted, and if so, the type of encryption protocol which is used.

        Supported encryption protocol identifiers are:

        * :py:class:`~pysnmp.hlapi.usmNoPrivProtocol` (default is *authKey* not given)
        * :py:class:`~pysnmp.hlapi.usmDESPrivProtocol` (default if *authKey* is given)
        * :py:class:`~pysnmp.hlapi.usm3DESEDEPrivProtocol`
        * :py:class:`~pysnmp.hlapi.usmAesCfb128Protocol`
        * :py:class:`~pysnmp.hlapi.usmAesCfb192Protocol`
        * :py:class:`~pysnmp.hlapi.usmAesCfb256Protocol`


    authKeyType: :py:class:`int`
        Type of `authKey` material. See :RFC:`3414#section-2.6` for
        technical explanation.

        Supported key types are:

        * :py:class:`~pysnmp.hlapi.usmKeyTypePassphrase` (default)
        * :py:class:`~pysnmp.hlapi.usmKeyTypeMaster`
        * :py:class:`~pysnmp.hlapi.usmKeyTypeLocalized`

    privKeyType: :py:class:`int`
        Type of `privKey` material. See :RFC:`3414#section-2.6` for
        technical explanation.

        Supported key types are:

        * :py:class:`~pysnmp.hlapi.usmKeyTypePassphrase` (default)
        * :py:class:`~pysnmp.hlapi.usmKeyTypeMaster`
        * :py:class:`~pysnmp.hlapi.usmKeyTypeLocalized`

    Notes
    -----
    If :py:class:`~pysnmp.hlapi.usmKeyTypeLocalized` is used when
    running a non-authoritative SNMP engine, USM key localization
    mechanism is not invoked. As a consequence, local SNMP engine
    configuration won't get automatically populated with remote SNMP
    engine's *securityEngineId*.

    Therefore peer SNMP engine's *securityEngineId* must be added
    to local configuration and associated with its localized keys.

    Alternatively, the magic *securityEngineId* value of five zeros
    (*0x0000000000*) can be used to refer to the localized keys that
    should be used with any unknown remote SNMP engine. This feature
    is specific to pysnmp.

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

    def __init__(self, userName,
                 authKey=None, privKey=None,
                 authProtocol=None, privProtocol=None,
                 securityEngineId=None,
                 securityName=None,
                 authKeyType=usmKeyTypePassphrase,
                 privKeyType=usmKeyTypePassphrase):
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

        self.securityEngineId = securityEngineId
        self.authKeyType = authKeyType
        self.privKeyType = privKeyType

    def __hash__(self):
        raise TypeError('%s is not hashable' % self.__class__.__name__)

    def __repr__(self):
        return '%s(userName=%r, authKey=<AUTHKEY>, privKey=<PRIVKEY>, authProtocol=%r, privProtocol=%r, securityEngineId=%r, securityName=%r, authKeyType=%r, privKeyType=%r)' % (
            self.__class__.__name__,
            self.userName,
            self.authProtocol,
            self.privProtocol,
            self.securityEngineId is None and '<DEFAULT>' or self.securityEngineId,
            self.securityName,
            self.authKeyType,
            self.privKeyType
        )

    def clone(self, userName=None,
              authKey=None, privKey=None,
              authProtocol=None, privProtocol=None,
              securityEngineId=None, securityName=None,
              authKeyType=None, privKeyType=None):
        return self.__class__(
            userName is None and self.userName or userName,
            authKey is None and self.authKey or authKey,
            privKey is None and self.privKey or privKey,
            authProtocol is None and self.authProtocol or authProtocol,
            privProtocol is None and self.privProtocol or privProtocol,
            securityEngineId is None and self.securityEngineId or securityEngineId,
            securityName is None and self.securityName or securityName,
            authKeyType is None and self.authKeyType or usmKeyTypePassphrase,
            privKeyType is None and self.privKeyType or usmKeyTypePassphrase
        )
