#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pyasn1.compat.octets import null
from pysnmp.carrier.asyncore.dgram import udp, udp6, unix
from pysnmp.proto.secmod.rfc3414.auth import hmacmd5, hmacsha, noauth
from pysnmp.proto.secmod.rfc3414.priv import des, nopriv
from pysnmp.proto.secmod.rfc3826.priv import aes
from pysnmp.proto.secmod.rfc7860.auth import hmacsha2
from pysnmp.proto.secmod.eso.priv import des3, aes192, aes256
from pysnmp.proto import rfc1902
from pysnmp.proto import rfc1905
from pysnmp import error
from pysnmp import debug

# A shortcut to popular constants

# Transports
snmpUDPDomain = udp.snmpUDPDomain
snmpUDP6Domain = udp6.snmpUDP6Domain
snmpLocalDomain = unix.snmpLocalDomain

# Auth protocol
usmHMACMD5AuthProtocol = hmacmd5.HmacMd5.serviceID
usmHMACSHAAuthProtocol = hmacsha.HmacSha.serviceID
usmHMAC128SHA224AuthProtocol = hmacsha2.HmacSha2.sha224ServiceID
usmHMAC192SHA256AuthProtocol = hmacsha2.HmacSha2.sha256ServiceID
usmHMAC256SHA384AuthProtocol = hmacsha2.HmacSha2.sha384ServiceID
usmHMAC384SHA512AuthProtocol = hmacsha2.HmacSha2.sha512ServiceID

usmNoAuthProtocol = noauth.NoAuth.serviceID
"""No authentication service"""

# Privacy protocol
usmDESPrivProtocol = des.Des.serviceID
usm3DESEDEPrivProtocol = des3.Des3.serviceID
usmAesCfb128Protocol = aes.Aes.serviceID
usmAesBlumenthalCfb192Protocol = aes192.AesBlumenthal192.serviceID  # semi-standard but not widely used
usmAesBlumenthalCfb256Protocol = aes256.AesBlumenthal256.serviceID  # semi-standard but not widely used
usmAesCfb192Protocol = aes192.Aes192.serviceID  # non-standard but used by many vendors
usmAesCfb256Protocol = aes256.Aes256.serviceID  # non-standard but used by many vendors
usmNoPrivProtocol = nopriv.NoPriv.serviceID

# USM key types (PYSNMP-USM-MIB::pysnmpUsmKeyType)
usmKeyTypePassphrase = 0
usmKeyTypeMaster = 1
usmKeyTypeLocalized = 2

# Auth services
authServices = {hmacmd5.HmacMd5.serviceID: hmacmd5.HmacMd5(),
                hmacsha.HmacSha.serviceID: hmacsha.HmacSha(),
                hmacsha2.HmacSha2.sha224ServiceID: hmacsha2.HmacSha2(hmacsha2.HmacSha2.sha224ServiceID),
                hmacsha2.HmacSha2.sha256ServiceID: hmacsha2.HmacSha2(hmacsha2.HmacSha2.sha256ServiceID),
                hmacsha2.HmacSha2.sha384ServiceID: hmacsha2.HmacSha2(hmacsha2.HmacSha2.sha384ServiceID),
                hmacsha2.HmacSha2.sha512ServiceID: hmacsha2.HmacSha2(hmacsha2.HmacSha2.sha512ServiceID),
                noauth.NoAuth.serviceID: noauth.NoAuth()}

# Privacy services
privServices = {des.Des.serviceID: des.Des(),
                des3.Des3.serviceID: des3.Des3(),
                aes.Aes.serviceID: aes.Aes(),
                aes192.AesBlumenthal192.serviceID: aes192.AesBlumenthal192(),
                aes256.AesBlumenthal256.serviceID: aes256.AesBlumenthal256(),
                aes192.Aes192.serviceID: aes192.Aes192(),  # non-standard
                aes256.Aes256.serviceID: aes256.Aes256(),  # non-standard
                nopriv.NoPriv.serviceID: nopriv.NoPriv()}


def __cookV1SystemInfo(snmpEngine, communityIndex):
    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    snmpEngineID, = mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineID')
    snmpCommunityEntry, = mibBuilder.importSymbols('SNMP-COMMUNITY-MIB', 'snmpCommunityEntry')
    tblIdx = snmpCommunityEntry.getInstIdFromIndices(communityIndex)
    return snmpCommunityEntry, tblIdx, snmpEngineID


def addV1System(snmpEngine, communityIndex, communityName,
                contextEngineId=None, contextName=None,
                transportTag=None, securityName=None):
    (snmpCommunityEntry, tblIdx,
     snmpEngineID) = __cookV1SystemInfo(snmpEngine, communityIndex)

    if contextEngineId is None:
        contextEngineId = snmpEngineID.syntax
    else:
        contextEngineId = snmpEngineID.syntax.clone(contextEngineId)

    if contextName is None:
        contextName = null

    securityName = securityName is not None and securityName or communityIndex

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpCommunityEntry.name + (8,) + tblIdx, 'destroy'),)
    )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpCommunityEntry.name + (1,) + tblIdx, communityIndex),
         (snmpCommunityEntry.name + (2,) + tblIdx, communityName),
         (snmpCommunityEntry.name + (3,) + tblIdx, securityName),
         (snmpCommunityEntry.name + (4,) + tblIdx, contextEngineId),
         (snmpCommunityEntry.name + (5,) + tblIdx, contextName),
         (snmpCommunityEntry.name + (6,) + tblIdx, transportTag),
         (snmpCommunityEntry.name + (7,) + tblIdx, 'nonVolatile'),
         (snmpCommunityEntry.name + (8,) + tblIdx, 'createAndGo'))
    )

    debug.logger & debug.flagSM and debug.logger(
        'addV1System: added new table entry '
        'communityIndex "%s" communityName "%s" securityName "%s" '
        'contextEngineId "%s" contextName "%s" transportTag '
        '"%s"' % (communityIndex, communityName, securityName,
                  contextEngineId, contextName, transportTag))


def delV1System(snmpEngine, communityIndex):
    (snmpCommunityEntry, tblIdx,
     snmpEngineID) = __cookV1SystemInfo(snmpEngine, communityIndex)
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpCommunityEntry.name + (8,) + tblIdx, 'destroy'),)
    )

    debug.logger & debug.flagSM and debug.logger(
        'delV1System: deleted table entry by communityIndex '
        '"%s"' % (communityIndex,))


def __cookV3UserInfo(snmpEngine, securityName, securityEngineId):
    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    snmpEngineID, = mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineID')

    if securityEngineId is None:
        securityEngineId = snmpEngineID.syntax
    else:
        securityEngineId = snmpEngineID.syntax.clone(securityEngineId)

    usmUserEntry, = mibBuilder.importSymbols('SNMP-USER-BASED-SM-MIB', 'usmUserEntry')
    tblIdx1 = usmUserEntry.getInstIdFromIndices(securityEngineId, securityName)

    pysnmpUsmSecretEntry, = mibBuilder.importSymbols('PYSNMP-USM-MIB', 'pysnmpUsmSecretEntry')
    tblIdx2 = pysnmpUsmSecretEntry.getInstIdFromIndices(securityName)

    return securityEngineId, usmUserEntry, tblIdx1, pysnmpUsmSecretEntry, tblIdx2


def addV3User(snmpEngine, userName,
              authProtocol=usmNoAuthProtocol, authKey=None,
              privProtocol=usmNoPrivProtocol, privKey=None,
              securityEngineId=None,
              securityName=None,
              authKeyType=usmKeyTypePassphrase,
              privKeyType=usmKeyTypePassphrase,
              # deprecated parameter
              contextEngineId=None):

    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    if securityName is None:
        securityName = userName

    if securityEngineId is None:  # backward compatibility
        securityEngineId = contextEngineId

    (securityEngineId, usmUserEntry, tblIdx1,
     pysnmpUsmSecretEntry, tblIdx2) = __cookV3UserInfo(
        snmpEngine, securityName, securityEngineId)

    # Load augmenting table before creating new row in base one
    pysnmpUsmKeyEntry, = mibBuilder.importSymbols('PYSNMP-USM-MIB', 'pysnmpUsmKeyEntry')

    # Load clone-from (may not be needed)
    zeroDotZero, = mibBuilder.importSymbols('SNMPv2-SMI', 'zeroDotZero')

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((usmUserEntry.name + (13,) + tblIdx1, 'destroy'),)
    )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((usmUserEntry.name + (2,) + tblIdx1, userName),
         (usmUserEntry.name + (3,) + tblIdx1, securityName),
         (usmUserEntry.name + (4,) + tblIdx1, zeroDotZero.name),
         (usmUserEntry.name + (5,) + tblIdx1, authProtocol),
         (usmUserEntry.name + (8,) + tblIdx1, privProtocol),
         (usmUserEntry.name + (13,) + tblIdx1, 'createAndGo'))
    )

    if authProtocol not in authServices:
        raise error.PySnmpError('Unknown auth protocol %s' % (authProtocol,))

    if privProtocol not in privServices:
        raise error.PySnmpError('Unknown privacy protocol %s' % (privProtocol,))

    pysnmpUsmKeyType, = mibBuilder.importSymbols('__PYSNMP-USM-MIB', 'pysnmpUsmKeyType')

    authKeyType = pysnmpUsmKeyType.syntax.clone(authKeyType)

    # Localize authentication key unless given

    authKey = authKey and rfc1902.OctetString(authKey)

    masterAuthKey = localAuthKey = authKey

    if authKeyType < usmKeyTypeMaster:  # pass phrase is given
        masterAuthKey = authServices[authProtocol].hashPassphrase(
            authKey or null
        )

    if authKeyType < usmKeyTypeLocalized:  # pass phrase or master key is given
        localAuthKey = authServices[authProtocol].localizeKey(
            masterAuthKey, securityEngineId
        )

    # Localize privacy key unless given

    privKeyType = pysnmpUsmKeyType.syntax.clone(privKeyType)

    privKey = privKey and rfc1902.OctetString(privKey)

    masterPrivKey = localPrivKey = privKey

    if privKeyType < usmKeyTypeMaster:  # pass phrase is given
        masterPrivKey = privServices[privProtocol].hashPassphrase(
            authProtocol, privKey or null
        )

    if privKeyType < usmKeyTypeLocalized:  # pass phrase or master key is given
        localPrivKey = privServices[privProtocol].localizeKey(
            authProtocol, masterPrivKey, securityEngineId
        )

    # Commit only the keys we have

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((pysnmpUsmKeyEntry.name + (1,) + tblIdx1, localAuthKey),)
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((pysnmpUsmKeyEntry.name + (2,) + tblIdx1, localPrivKey),)
    )

    if authKeyType < usmKeyTypeLocalized:
        snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
            ((pysnmpUsmKeyEntry.name + (3,) + tblIdx1, masterAuthKey),)
        )

    if privKeyType < usmKeyTypeLocalized:
        snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
            ((pysnmpUsmKeyEntry.name + (4,) + tblIdx1, masterPrivKey),)
        )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((pysnmpUsmSecretEntry.name + (4,) + tblIdx2, 'destroy'),)
    )

    # Commit plain-text pass-phrases if we have them

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((pysnmpUsmSecretEntry.name + (4,) + tblIdx2, 'createAndGo'),)
    )

    if authKeyType < usmKeyTypeMaster:
        snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
            ((pysnmpUsmSecretEntry.name + (1,) + tblIdx2, userName),
             (pysnmpUsmSecretEntry.name + (2,) + tblIdx2, authKey))
        )

    if privKeyType < usmKeyTypeMaster:
        snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
            ((pysnmpUsmSecretEntry.name + (1,) + tblIdx2, userName),
             (pysnmpUsmSecretEntry.name + (3,) + tblIdx2, privKey))
        )

    debug.logger & debug.flagSM and debug.logger(
        'addV3User: added new table entries '
        'userName "%s" securityName "%s" authProtocol %s '
        'privProtocol %s localAuthKey "%s" localPrivKey "%s" '
        'masterAuthKey "%s" masterPrivKey "%s" authKey "%s" '
        'privKey "%s" by index securityName "%s" securityEngineId '
        '"%s"' % (
            userName, securityName, authProtocol, privProtocol,
            localAuthKey and localAuthKey.prettyPrint(),
            localPrivKey and localPrivKey.prettyPrint(),
            masterAuthKey and masterAuthKey.prettyPrint(),
            masterPrivKey and masterPrivKey.prettyPrint(),
            authKey and authKey.prettyPrint(),
            privKey and privKey.prettyPrint(),
            securityName,
            securityEngineId.prettyPrint()))


def delV3User(snmpEngine,
              userName,
              securityEngineId=None,
              # deprecated parameters follow
              contextEngineId=None):
    if securityEngineId is None:  # backward compatibility
        securityEngineId = contextEngineId
    (securityEngineId, usmUserEntry, tblIdx1, pysnmpUsmSecretEntry,
     tblIdx2) = __cookV3UserInfo(snmpEngine, userName, securityEngineId)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((usmUserEntry.name + (13,) + tblIdx1, 'destroy'),)
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((pysnmpUsmSecretEntry.name + (4,) + tblIdx2, 'destroy'),)
    )

    debug.logger & debug.flagSM and debug.logger(
        'delV3User: deleted table entries by index '
        'userName "%s" securityEngineId '
        '"%s"' % (
            userName,
            securityEngineId.prettyPrint()))

    # Drop all derived rows
    varBinds = initialVarBinds = (
        (usmUserEntry.name + (1,), None),  # usmUserEngineID
        (usmUserEntry.name + (2,), None),  # usmUserName
        (usmUserEntry.name + (4,), None)  # usmUserCloneFrom
    )

    while varBinds:
        varBinds = snmpEngine.msgAndPduDsp.mibInstrumController.readNextVars(
            varBinds
        )
        if varBinds[0][1].isSameTypeWith(rfc1905.endOfMibView):
            break
        if varBinds[0][0][:len(initialVarBinds[0][0])] != initialVarBinds[0][0]:
            break
        elif varBinds[2][1] == tblIdx1:  # cloned from this entry
            delV3User(snmpEngine, varBinds[1][1], varBinds[0][1])
            varBinds = initialVarBinds


def __cookTargetParamsInfo(snmpEngine, name):
    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    snmpTargetParamsEntry, = mibBuilder.importSymbols('SNMP-TARGET-MIB', 'snmpTargetParamsEntry')
    tblIdx = snmpTargetParamsEntry.getInstIdFromIndices(name)
    return snmpTargetParamsEntry, tblIdx


# mpModel: 0 == SNMPv1, 1 == SNMPv2c, 3 == SNMPv3
def addTargetParams(snmpEngine, name, securityName, securityLevel, mpModel=3):
    if mpModel == 0:
        securityModel = 1
    elif mpModel in (1, 2):
        securityModel = 2
    elif mpModel == 3:
        securityModel = 3
    else:
        raise error.PySnmpError('Unknown MP model %s' % mpModel)

    snmpTargetParamsEntry, tblIdx = __cookTargetParamsInfo(snmpEngine, name)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpTargetParamsEntry.name + (7,) + tblIdx, 'destroy'),)
    )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpTargetParamsEntry.name + (1,) + tblIdx, name),
         (snmpTargetParamsEntry.name + (2,) + tblIdx, mpModel),
         (snmpTargetParamsEntry.name + (3,) + tblIdx, securityModel),
         (snmpTargetParamsEntry.name + (4,) + tblIdx, securityName),
         (snmpTargetParamsEntry.name + (5,) + tblIdx, securityLevel),
         (snmpTargetParamsEntry.name + (7,) + tblIdx, 'createAndGo'))
    )


def delTargetParams(snmpEngine, name):
    snmpTargetParamsEntry, tblIdx = __cookTargetParamsInfo(snmpEngine, name)
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpTargetParamsEntry.name + (7,) + tblIdx, 'destroy'),)
    )


def __cookTargetAddrInfo(snmpEngine, addrName):
    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    snmpTargetAddrEntry, = mibBuilder.importSymbols('SNMP-TARGET-MIB', 'snmpTargetAddrEntry')
    snmpSourceAddrEntry, = mibBuilder.importSymbols('PYSNMP-SOURCE-MIB', 'snmpSourceAddrEntry')
    tblIdx = snmpTargetAddrEntry.getInstIdFromIndices(addrName)
    return snmpTargetAddrEntry, snmpSourceAddrEntry, tblIdx


def addTargetAddr(snmpEngine, addrName, transportDomain, transportAddress,
                  params, timeout=None, retryCount=None, tagList=null,
                  sourceAddress=None):
    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    (snmpTargetAddrEntry, snmpSourceAddrEntry,
     tblIdx) = __cookTargetAddrInfo(snmpEngine, addrName)

    if transportDomain[:len(snmpUDPDomain)] == snmpUDPDomain:
        SnmpUDPAddress, = mibBuilder.importSymbols('SNMPv2-TM', 'SnmpUDPAddress')
        transportAddress = SnmpUDPAddress(transportAddress)
        if sourceAddress is None:
            sourceAddress = ('0.0.0.0', 0)
        sourceAddress = SnmpUDPAddress(sourceAddress)
    elif transportDomain[:len(snmpUDP6Domain)] == snmpUDP6Domain:
        TransportAddressIPv6, = mibBuilder.importSymbols('TRANSPORT-ADDRESS-MIB', 'TransportAddressIPv6')
        transportAddress = TransportAddressIPv6(transportAddress)
        if sourceAddress is None:
            sourceAddress = ('::', 0)
        sourceAddress = TransportAddressIPv6(sourceAddress)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpTargetAddrEntry.name + (9,) + tblIdx, 'destroy'),)
    )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpTargetAddrEntry.name + (1,) + tblIdx, addrName),
         (snmpTargetAddrEntry.name + (2,) + tblIdx, transportDomain),
         (snmpTargetAddrEntry.name + (3,) + tblIdx, transportAddress),
         (snmpTargetAddrEntry.name + (4,) + tblIdx, timeout),
         (snmpTargetAddrEntry.name + (5,) + tblIdx, retryCount),
         (snmpTargetAddrEntry.name + (6,) + tblIdx, tagList),
         (snmpTargetAddrEntry.name + (7,) + tblIdx, params),
         (snmpSourceAddrEntry.name + (1,) + tblIdx, sourceAddress),
         (snmpTargetAddrEntry.name + (9,) + tblIdx, 'createAndGo'))
    )


def delTargetAddr(snmpEngine, addrName):
    (snmpTargetAddrEntry, snmpSourceAddrEntry,
     tblIdx) = __cookTargetAddrInfo(snmpEngine, addrName)
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpTargetAddrEntry.name + (9,) + tblIdx, 'destroy'),)
    )


def addTransport(snmpEngine, transportDomain, transport):
    if snmpEngine.transportDispatcher:
        if not transport.isCompatibleWithDispatcher(snmpEngine.transportDispatcher):
            raise error.PySnmpError(
                'Transport %r is not compatible with dispatcher %r' % (transport, snmpEngine.transportDispatcher))
    else:
        snmpEngine.registerTransportDispatcher(
            transport.protoTransportDispatcher()
        )
        # here we note that we have created transportDispatcher automatically
        snmpEngine.setUserContext(automaticTransportDispatcher=0)

    snmpEngine.transportDispatcher.registerTransport(transportDomain, transport)
    automaticTransportDispatcher = snmpEngine.getUserContext(
        'automaticTransportDispatcher'
    )
    if automaticTransportDispatcher is not None:
        snmpEngine.setUserContext(
            automaticTransportDispatcher=automaticTransportDispatcher + 1
        )


def getTransport(snmpEngine, transportDomain):
    if not snmpEngine.transportDispatcher:
        return
    try:
        return snmpEngine.transportDispatcher.getTransport(transportDomain)
    except error.PySnmpError:
        return


def delTransport(snmpEngine, transportDomain):
    if not snmpEngine.transportDispatcher:
        return
    transport = getTransport(snmpEngine, transportDomain)
    snmpEngine.transportDispatcher.unregisterTransport(transportDomain)
    # automatically shutdown automatically created transportDispatcher
    automaticTransportDispatcher = snmpEngine.getUserContext(
        'automaticTransportDispatcher'
    )
    if automaticTransportDispatcher is not None:
        automaticTransportDispatcher -= 1
        snmpEngine.setUserContext(
            automaticTransportDispatcher=automaticTransportDispatcher
        )
        if not automaticTransportDispatcher:
            snmpEngine.transportDispatcher.closeDispatcher()
            snmpEngine.unregisterTransportDispatcher()
            snmpEngine.delUserContext(automaticTransportDispatcher)
    return transport


addSocketTransport = addTransport
delSocketTransport = delTransport


# VACM shortcuts

def __cookVacmContextInfo(snmpEngine, contextName):
    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder
    vacmContextEntry, = mibBuilder.importSymbols('SNMP-VIEW-BASED-ACM-MIB', 'vacmContextEntry')
    tblIdx = vacmContextEntry.getInstIdFromIndices(contextName)
    return vacmContextEntry, tblIdx


def addContext(snmpEngine, contextName):
    vacmContextEntry, tblIdx = __cookVacmContextInfo(snmpEngine, contextName)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmContextEntry.name + (2,) + tblIdx, 'destroy'),)
    )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmContextEntry.name + (1,) + tblIdx, contextName),
         (vacmContextEntry.name + (2,) + tblIdx, 'createAndGo'))
    )


def delContext(snmpEngine, contextName):
    vacmContextEntry, tblIdx = __cookVacmContextInfo(snmpEngine, contextName)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmContextEntry.name + (2,) + tblIdx, 'destroy'),)
    )


def __cookVacmGroupInfo(snmpEngine, securityModel, securityName):
    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    vacmSecurityToGroupEntry, = mibBuilder.importSymbols('SNMP-VIEW-BASED-ACM-MIB',
                                                         'vacmSecurityToGroupEntry')
    tblIdx = vacmSecurityToGroupEntry.getInstIdFromIndices(securityModel,
                                                           securityName)
    return vacmSecurityToGroupEntry, tblIdx


def addVacmGroup(snmpEngine, groupName, securityModel, securityName):
    (vacmSecurityToGroupEntry,
     tblIdx) = __cookVacmGroupInfo(snmpEngine, securityModel, securityName)
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmSecurityToGroupEntry.name + (5,) + tblIdx, 'destroy'),)
    )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmSecurityToGroupEntry.name + (1,) + tblIdx, securityModel),
         (vacmSecurityToGroupEntry.name + (2,) + tblIdx, securityName),
         (vacmSecurityToGroupEntry.name + (3,) + tblIdx, groupName),
         (vacmSecurityToGroupEntry.name + (5,) + tblIdx, 'createAndGo'))
    )


def delVacmGroup(snmpEngine, securityModel, securityName):
    vacmSecurityToGroupEntry, tblIdx = __cookVacmGroupInfo(
        snmpEngine, securityModel, securityName
    )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmSecurityToGroupEntry.name + (5,) + tblIdx, 'destroy'),)
    )


def __cookVacmAccessInfo(snmpEngine, groupName, contextName, securityModel,
                         securityLevel):
    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    vacmAccessEntry, = mibBuilder.importSymbols('SNMP-VIEW-BASED-ACM-MIB', 'vacmAccessEntry')
    tblIdx = vacmAccessEntry.getInstIdFromIndices(groupName, contextName,
                                                  securityModel, securityLevel)
    return vacmAccessEntry, tblIdx


def addVacmAccess(snmpEngine, groupName, contextPrefix, securityModel,
                  securityLevel, contextMatch, readView, writeView, notifyView):
    vacmAccessEntry, tblIdx = __cookVacmAccessInfo(
        snmpEngine, groupName, contextPrefix, securityModel,
        securityLevel)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmAccessEntry.name + (9,) + tblIdx, 'destroy'),)
    )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmAccessEntry.name + (1,) + tblIdx, contextPrefix),
         (vacmAccessEntry.name + (2,) + tblIdx, securityModel),
         (vacmAccessEntry.name + (3,) + tblIdx, securityLevel),
         (vacmAccessEntry.name + (4,) + tblIdx, contextMatch),
         (vacmAccessEntry.name + (5,) + tblIdx, readView),
         (vacmAccessEntry.name + (6,) + tblIdx, writeView),
         (vacmAccessEntry.name + (7,) + tblIdx, notifyView),
         (vacmAccessEntry.name + (9,) + tblIdx, 'createAndGo'))
    )


def delVacmAccess(snmpEngine, groupName, contextPrefix, securityModel,
                  securityLevel):
    vacmAccessEntry, tblIdx = __cookVacmAccessInfo(
        snmpEngine, groupName, contextPrefix, securityModel, securityLevel)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmAccessEntry.name + (9,) + tblIdx, 'destroy'),)
    )


def __cookVacmViewInfo(snmpEngine, viewName, subTree):
    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    vacmViewTreeFamilyEntry, = mibBuilder.importSymbols(
        'SNMP-VIEW-BASED-ACM-MIB', 'vacmViewTreeFamilyEntry'
    )
    tblIdx = vacmViewTreeFamilyEntry.getInstIdFromIndices(viewName, subTree)
    return vacmViewTreeFamilyEntry, tblIdx


def addVacmView(snmpEngine, viewName, viewType, subTree, subTreeMask):
    vacmViewTreeFamilyEntry, tblIdx = __cookVacmViewInfo(
        snmpEngine, viewName, subTree)

    # Allow bitmask specification in form of an OID
    if rfc1902.OctetString('.').asOctets() in rfc1902.OctetString(subTreeMask):
        subTreeMask = rfc1902.ObjectIdentifier(subTreeMask)

    if isinstance(subTreeMask, rfc1902.ObjectIdentifier):
        subTreeMask = tuple(subTreeMask)
        if len(subTreeMask) < len(subTree):
            subTreeMask += (1,) * (len(subTree) - len(subTreeMask))

        subTreeMask = rfc1902.OctetString.fromBinaryString(
            ''.join(str(x) for x in subTreeMask))

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmViewTreeFamilyEntry.name + (6,) + tblIdx, 'destroy'),)
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmViewTreeFamilyEntry.name + (1,) + tblIdx, viewName),
         (vacmViewTreeFamilyEntry.name + (2,) + tblIdx, subTree),
         (vacmViewTreeFamilyEntry.name + (3,) + tblIdx, subTreeMask),
         (vacmViewTreeFamilyEntry.name + (4,) + tblIdx, viewType),
         (vacmViewTreeFamilyEntry.name + (6,) + tblIdx, 'createAndGo'))
    )


def delVacmView(snmpEngine, viewName, subTree):
    vacmViewTreeFamilyEntry, tblIdx = __cookVacmViewInfo(snmpEngine, viewName,
                                                         subTree)
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmViewTreeFamilyEntry.name + (6,) + tblIdx, 'destroy'),)
    )


# VACM simplicity wrappers

def __cookVacmUserInfo(snmpEngine, securityModel, securityName, securityLevel):
    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    groupName = 'v-%s-%d' % (hash(securityName), securityModel)
    SnmpSecurityLevel, = mibBuilder.importSymbols('SNMP-FRAMEWORK-MIB', 'SnmpSecurityLevel')
    securityLevel = SnmpSecurityLevel(securityLevel)
    return (groupName, securityLevel,
            'r' + groupName, 'w' + groupName, 'n' + groupName)


def addVacmUser(snmpEngine, securityModel, securityName, securityLevel,
                readSubTree=(), writeSubTree=(), notifySubTree=(),
                contextName=null):
    (groupName, securityLevel, readView, writeView,
     notifyView) = __cookVacmUserInfo(snmpEngine, securityModel, securityName,
                                      securityLevel)
    addContext(snmpEngine, contextName)
    addVacmGroup(snmpEngine, groupName, securityModel, securityName)
    addVacmAccess(snmpEngine, groupName, contextName, securityModel,
                  securityLevel, 'exact', readView, writeView, notifyView)
    if readSubTree:
        addVacmView(snmpEngine, readView, 'included', readSubTree, null)
    if writeSubTree:
        addVacmView(snmpEngine, writeView, 'included', writeSubTree, null)
    if notifySubTree:
        addVacmView(snmpEngine, notifyView, 'included', notifySubTree, null)


def delVacmUser(snmpEngine, securityModel, securityName, securityLevel,
                readSubTree=(), writeSubTree=(), notifySubTree=(),
                contextName=null):
    (groupName, securityLevel, readView, writeView,
     notifyView) = __cookVacmUserInfo(snmpEngine, securityModel,
                                      securityName, securityLevel)
    delContext(snmpEngine, contextName)
    delVacmGroup(snmpEngine, securityModel, securityName)
    delVacmAccess(snmpEngine, groupName, contextName, securityModel, securityLevel)
    if readSubTree:
        delVacmView(
            snmpEngine, readView, readSubTree
        )
    if writeSubTree:
        delVacmView(
            snmpEngine, writeView, writeSubTree
        )
    if notifySubTree:
        delVacmView(
            snmpEngine, notifyView, notifySubTree
        )


# Obsolete shortcuts for add/delVacmUser() wrappers

def addRoUser(snmpEngine, securityModel, securityName, securityLevel,
              subTree, contextName=null):
    addVacmUser(snmpEngine, securityModel, securityName, securityLevel,
                subTree, contextName=contextName)


def delRoUser(snmpEngine, securityModel, securityName, securityLevel,
              subTree, contextName=null):
    delVacmUser(snmpEngine, securityModel, securityName, securityLevel,
                subTree, contextName=contextName)


def addRwUser(snmpEngine, securityModel, securityName, securityLevel,
              subTree, contextName=null):
    addVacmUser(snmpEngine, securityModel, securityName, securityLevel,
                subTree, subTree, contextName=contextName)


def delRwUser(snmpEngine, securityModel, securityName, securityLevel,
              subTree, contextName=null):
    delVacmUser(snmpEngine, securityModel, securityName, securityLevel,
                subTree, subTree, contextName=contextName)


def addTrapUser(snmpEngine, securityModel, securityName,
                securityLevel, subTree, contextName=null):
    addVacmUser(snmpEngine, securityModel, securityName, securityLevel,
                (), (), subTree, contextName=contextName)


def delTrapUser(snmpEngine, securityModel, securityName,
                securityLevel, subTree, contextName=null):
    delVacmUser(snmpEngine, securityModel, securityName, securityLevel,
                (), (), subTree, contextName=contextName)


# Notification target setup

def __cookNotificationTargetInfo(snmpEngine, notificationName, paramsName,
                                 filterSubtree=None):
    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    snmpNotifyEntry, = mibBuilder.importSymbols('SNMP-NOTIFICATION-MIB', 'snmpNotifyEntry')
    tblIdx1 = snmpNotifyEntry.getInstIdFromIndices(notificationName)

    snmpNotifyFilterProfileEntry, = mibBuilder.importSymbols('SNMP-NOTIFICATION-MIB',
                                                             'snmpNotifyFilterProfileEntry')
    tblIdx2 = snmpNotifyFilterProfileEntry.getInstIdFromIndices(paramsName)

    profileName = '%s-filter' % hash(notificationName)

    if filterSubtree:
        snmpNotifyFilterEntry, = mibBuilder.importSymbols('SNMP-NOTIFICATION-MIB',
                                                          'snmpNotifyFilterEntry')
        tblIdx3 = snmpNotifyFilterEntry.getInstIdFromIndices(profileName,
                                                             filterSubtree)
    else:
        snmpNotifyFilterEntry = tblIdx3 = None

    return (snmpNotifyEntry, tblIdx1,
            snmpNotifyFilterProfileEntry, tblIdx2, profileName,
            snmpNotifyFilterEntry, tblIdx3)


def addNotificationTarget(snmpEngine, notificationName, paramsName,
                          transportTag, notifyType=None, filterSubtree=None,
                          filterMask=None, filterType=None):
    (snmpNotifyEntry, tblIdx1, snmpNotifyFilterProfileEntry, tblIdx2,
     profileName, snmpNotifyFilterEntry,
     tblIdx3) = __cookNotificationTargetInfo(snmpEngine, notificationName,
                                             paramsName, filterSubtree)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyEntry.name + (5,) + tblIdx1, 'destroy'),)
    )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyEntry.name + (2,) + tblIdx1, transportTag),
         (snmpNotifyEntry.name + (3,) + tblIdx1, notifyType),
         (snmpNotifyEntry.name + (5,) + tblIdx1, 'createAndGo'))
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyFilterProfileEntry.name + (3,) + tblIdx2, 'destroy'),)
    )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyFilterProfileEntry.name + (1,) + tblIdx2, profileName),
         (snmpNotifyFilterProfileEntry.name + (3,) + tblIdx2, 'createAndGo'))
    )

    if not snmpNotifyFilterEntry:
        return

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyFilterEntry.name + (5,) + tblIdx3, 'destroy'),)
    )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyFilterEntry.name + (1,) + tblIdx3, filterSubtree),
         (snmpNotifyFilterEntry.name + (2,) + tblIdx3, filterMask),
         (snmpNotifyFilterEntry.name + (3,) + tblIdx3, filterType),
         (snmpNotifyFilterEntry.name + (5,) + tblIdx3, 'createAndGo'))
    )


def delNotificationTarget(snmpEngine, notificationName, paramsName,
                          filterSubtree=None):
    (snmpNotifyEntry, tblIdx1, snmpNotifyFilterProfileEntry,
     tblIdx2, profileName, snmpNotifyFilterEntry,
     tblIdx3) = __cookNotificationTargetInfo(snmpEngine, notificationName,
                                             paramsName, filterSubtree)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyEntry.name + (5,) + tblIdx1, 'destroy'),)
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyFilterProfileEntry.name + (3,) + tblIdx2, 'destroy'),)
    )

    if not snmpNotifyFilterEntry:
        return

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyFilterEntry.name + (5,) + tblIdx3, 'destroy'),)
    )


# rfc3415: A.1
def setInitialVacmParameters(snmpEngine):
    # rfc3415: A.1.1 --> initial-semi-security-configuration

    # rfc3415: A.1.2
    addContext(snmpEngine, "")

    # rfc3415: A.1.3
    addVacmGroup(snmpEngine, "initial", 3, "initial")

    # rfc3415: A.1.4
    addVacmAccess(snmpEngine, "initial", "", 3, "noAuthNoPriv", "exact",
                  "restricted", None, "restricted")
    addVacmAccess(snmpEngine, "initial", "", 3, "authNoPriv", "exact",
                  "internet", "internet", "internet")
    addVacmAccess(snmpEngine, "initial", "", 3, "authPriv", "exact",
                  "internet", "internet", "internet")

    # rfc3415: A.1.5 (semi-secure)
    addVacmView(snmpEngine, "internet",
                "included", (1, 3, 6, 1), "")
    addVacmView(snmpEngine, "restricted",
                "included", (1, 3, 6, 1, 2, 1, 1), "")
    addVacmView(snmpEngine, "restricted",
                "included", (1, 3, 6, 1, 2, 1, 11), "")
    addVacmView(snmpEngine, "restricted",
                "included", (1, 3, 6, 1, 6, 3, 10, 2, 1), "")
    addVacmView(snmpEngine, "restricted",
                "included", (1, 3, 6, 1, 6, 3, 11, 2, 1), "")
    addVacmView(snmpEngine, "restricted",
                "included", (1, 3, 6, 1, 6, 3, 15, 1, 1), "")
