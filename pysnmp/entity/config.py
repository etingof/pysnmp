#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pyasn1.compat.octets import null

from pysnmp import error
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.carrier.asyncore.dgram import udp6
from pysnmp.proto.secmod.rfc3414.auth import hmacmd5
from pysnmp.proto.secmod.rfc3414.auth import hmacsha
from pysnmp.proto.secmod.rfc3414.auth import noauth
from pysnmp.proto.secmod.rfc3414.priv import des
from pysnmp.proto.secmod.rfc3414.priv import nopriv
from pysnmp.proto.secmod.rfc3826.priv import aes
from pysnmp.proto.secmod.rfc7860.auth import hmacsha2
from pysnmp.proto.secmod.eso.priv import aes192
from pysnmp.proto.secmod.eso.priv import aes256
from pysnmp.proto.secmod.eso.priv import des3
from pysnmp.proto import rfc1902
from pysnmp.proto import rfc1905
from pysnmp import error
from pysnmp import debug

# A shortcut to popular constants

# Transports
SNMP_UDP_DOMAIN = udp.SNMP_UDP_DOMAIN
SNMP_UDP6_DOMAIN = udp6.SNMP_UDP6_DOMAIN

# Auth protocol
USM_AUTH_HMAC96_MD5 = hmacmd5.HmacMd5.SERVICE_ID
USM_AUTH_HMAC96_SHA = hmacsha.HmacSha.SERVICE_ID
USM_AUTH_HMAC128_SHA224 = hmacsha2.HmacSha2.SHA224_SERVICE_ID
USM_AUTH_HMAC192_SHA256 = hmacsha2.HmacSha2.SHA256_SERVICE_ID
USM_AUTH_HMAC256_SHA384 = hmacsha2.HmacSha2.SHA384_SERVICE_ID
USM_AUTH_HMAC384_SHA512 = hmacsha2.HmacSha2.SHA512_SERVICE_ID

USM_AUTH_NONE = noauth.NoAuth.SERVICE_ID
"""No authentication service"""

# Privacy protocol
USM_PRIV_CBC56_DES = des.Des.SERVICE_ID
USM_PRIV_CBC168_3DES = des3.Des3.SERVICE_ID
USM_PRIV_CFB128_AES = aes.Aes.SERVICE_ID
USM_PRIV_CFB192_AES = aes192.Aes192.SERVICE_ID  # non-standard but used by many vendors
USM_PRIV_CFB256_AES = aes256.Aes256.SERVICE_ID  # non-standard but used by many vendors
USM_PRIV_CFB192_AES_BLUMENTHAL = aes192.AesBlumenthal192.SERVICE_ID  # semi-standard but not widely used
USM_PRIV_CFB256_AES_BLUMENTHAL = aes256.AesBlumenthal256.SERVICE_ID  # semi-standard but not widely used

USM_PRIV_NONE = nopriv.NoPriv.SERVICE_ID

# USM key types (PYSNMP-USM-MIB::pysnmpUsmKeyType)
USM_KEY_TYPE_PASSPHRASE = 0
USM_KEY_TYPE_MASTER = 1
USM_KEY_TYPE_LOCALIZED = 2

AUTH_SERVICES = {
    hmacmd5.HmacMd5.SERVICE_ID: hmacmd5.HmacMd5(),
    hmacsha.HmacSha.SERVICE_ID: hmacsha.HmacSha(),
    hmacsha2.HmacSha2.SHA224_SERVICE_ID: hmacsha2.HmacSha2(hmacsha2.HmacSha2.SHA224_SERVICE_ID),
    hmacsha2.HmacSha2.SHA256_SERVICE_ID: hmacsha2.HmacSha2(hmacsha2.HmacSha2.SHA256_SERVICE_ID),
    hmacsha2.HmacSha2.SHA384_SERVICE_ID: hmacsha2.HmacSha2(hmacsha2.HmacSha2.SHA384_SERVICE_ID),
    hmacsha2.HmacSha2.SHA512_SERVICE_ID: hmacsha2.HmacSha2(hmacsha2.HmacSha2.SHA512_SERVICE_ID),
    noauth.NoAuth.SERVICE_ID: noauth.NoAuth()
}

PRIV_SERVICES = {
    des.Des.SERVICE_ID: des.Des(),
    des3.Des3.SERVICE_ID: des3.Des3(),
    aes.Aes.SERVICE_ID: aes.Aes(),
    aes192.AesBlumenthal192.SERVICE_ID: aes192.AesBlumenthal192(),
    aes256.AesBlumenthal256.SERVICE_ID: aes256.AesBlumenthal256(),
    aes192.Aes192.SERVICE_ID: aes192.Aes192(),  # non-standard
    aes256.Aes256.SERVICE_ID: aes256.Aes256(),  # non-standard
    nopriv.NoPriv.SERVICE_ID: nopriv.NoPriv()
}


# This module uses Management Instrumentation subsystem in purely
# synchronous manner. The assumption is that the Management
# Instrumentation calls never yield control but block.

def __cookV1SystemInfo(snmpEngine, communityIndex):
    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    snmpEngineID, = mibBuilder.importSymbols(
        '__SNMP-FRAMEWORK-MIB', 'snmpEngineID')
    snmpCommunityEntry, = mibBuilder.importSymbols(
        'SNMP-COMMUNITY-MIB', 'snmpCommunityEntry')

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

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpCommunityEntry.name + (8,) + tblIdx, 'destroy'),
        snmpEngine=snmpEngine
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpCommunityEntry.name + (1,) + tblIdx, communityIndex),
        (snmpCommunityEntry.name + (2,) + tblIdx, communityName),
        (snmpCommunityEntry.name + (3,) + tblIdx, securityName),
        (snmpCommunityEntry.name + (4,) + tblIdx, contextEngineId),
        (snmpCommunityEntry.name + (5,) + tblIdx, contextName),
        (snmpCommunityEntry.name + (6,) + tblIdx, transportTag),
        (snmpCommunityEntry.name + (7,) + tblIdx, 'nonVolatile'),
        (snmpCommunityEntry.name + (8,) + tblIdx, 'createAndGo'),
        snmpEngine=snmpEngine
    )

    debug.logger & debug.FLAG_SM and debug.logger(
        'addV1System: added new table entry '
        'communityIndex "%s" communityName "%s" securityName "%s" '
        'contextEngineId "%s" contextName "%s" transportTag '
        '"%s"' % (communityIndex, communityName, securityName,
                  contextEngineId, contextName, transportTag))


def delV1System(snmpEngine, communityIndex):
    (snmpCommunityEntry, tblIdx,
     snmpEngineID) = __cookV1SystemInfo(snmpEngine, communityIndex)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpCommunityEntry.name + (8,) + tblIdx, 'destroy'),
        snmpEngine=snmpEngine
    )

    debug.logger & debug.FLAG_SM and debug.logger(
        'delV1System: deleted table entry by communityIndex '
        '"%s"' % (communityIndex,))


def __cookV3UserInfo(snmpEngine, securityName, securityEngineId):
    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    snmpEngineID, = mibBuilder.importSymbols(
        '__SNMP-FRAMEWORK-MIB', 'snmpEngineID')

    if securityEngineId is None:
        securityEngineId = snmpEngineID.syntax

    else:
        securityEngineId = snmpEngineID.syntax.clone(securityEngineId)

    usmUserEntry, = mibBuilder.importSymbols(
        'SNMP-USER-BASED-SM-MIB', 'usmUserEntry')

    tblIdx1 = usmUserEntry.getInstIdFromIndices(securityEngineId, securityName)

    pysnmpUsmSecretEntry, = mibBuilder.importSymbols(
        'PYSNMP-USM-MIB', 'pysnmpUsmSecretEntry')

    tblIdx2 = pysnmpUsmSecretEntry.getInstIdFromIndices(securityName)

    return securityEngineId, usmUserEntry, tblIdx1, pysnmpUsmSecretEntry, tblIdx2


def addV3User(snmpEngine, userName,
              authProtocol=USM_AUTH_NONE, authKey=None,
              privProtocol=USM_PRIV_NONE, privKey=None,
              securityEngineId=None,
              securityName=None,
              authKeyType=USM_KEY_TYPE_PASSPHRASE,
              privKeyType=USM_KEY_TYPE_PASSPHRASE):

    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    if securityName is None:
        securityName = userName

    (securityEngineId, usmUserEntry, tblIdx1,
     pysnmpUsmSecretEntry, tblIdx2) = __cookV3UserInfo(
        snmpEngine, securityName, securityEngineId)

    # Load augmenting table before creating new row in base one
    pysnmpUsmKeyEntry, = mibBuilder.importSymbols(
        'PYSNMP-USM-MIB', 'pysnmpUsmKeyEntry')

    # Load clone-from (may not be needed)
    zeroDotZero, = mibBuilder.importSymbols(
        'SNMPv2-SMI', 'zeroDotZero')

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (usmUserEntry.name + (13,) + tblIdx1, 'destroy'),
        snmpEngine=snmpEngine
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (usmUserEntry.name + (2,) + tblIdx1, userName),
        (usmUserEntry.name + (3,) + tblIdx1, securityName),
        (usmUserEntry.name + (4,) + tblIdx1, zeroDotZero.name),
        (usmUserEntry.name + (5,) + tblIdx1, authProtocol),
        (usmUserEntry.name + (8,) + tblIdx1, privProtocol),
        (usmUserEntry.name + (13,) + tblIdx1, 'createAndGo'),
        snmpEngine=snmpEngine
    )

    if authProtocol not in AUTH_SERVICES:
        raise error.PySnmpError('Unknown auth protocol %s' % (authProtocol,))

    if privProtocol not in PRIV_SERVICES:
        raise error.PySnmpError('Unknown privacy protocol %s' % (privProtocol,))

    pysnmpUsmKeyType, = mibBuilder.importSymbols(
        '__PYSNMP-USM-MIB', 'pysnmpUsmKeyType')

    authKeyType = pysnmpUsmKeyType.syntax.clone(authKeyType)

    # Localize authentication key unless given

    authKey = authKey and rfc1902.OctetString(authKey)

    masterAuthKey = localAuthKey = authKey

    if authKeyType < USM_KEY_TYPE_MASTER:  # master key is not given
        masterAuthKey = AUTH_SERVICES[authProtocol].hashPassphrase(
            authKey or null
        )

    if authKeyType < USM_KEY_TYPE_LOCALIZED:  # localized key is not given
        localAuthKey = AUTH_SERVICES[authProtocol].localizeKey(
            masterAuthKey, securityEngineId
        )

    # Localize privacy key unless given

    privKeyType = pysnmpUsmKeyType.syntax.clone(privKeyType)

    privKey = privKey and rfc1902.OctetString(privKey)

    masterPrivKey = localPrivKey = privKey

    if privKeyType < USM_KEY_TYPE_MASTER:  # master key is not given
        masterPrivKey = PRIV_SERVICES[privProtocol].hashPassphrase(
            authProtocol, privKey or null
        )

    if privKeyType < USM_KEY_TYPE_LOCALIZED:  # localized key is not given
        localPrivKey = PRIV_SERVICES[privProtocol].localizeKey(
            authProtocol, masterPrivKey, securityEngineId
        )

    # Commit only the keys we have

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (pysnmpUsmKeyEntry.name + (1,) + tblIdx1, localAuthKey),
         snmpEngine=snmpEngine
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (pysnmpUsmKeyEntry.name + (2,) + tblIdx1, localPrivKey),
        snmpEngine = snmpEngine
    )

    if authKeyType < USM_KEY_TYPE_LOCALIZED:
        snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
            (pysnmpUsmKeyEntry.name + (3,) + tblIdx1, masterAuthKey),
             snmpEngine=snmpEngine
        )

    if privKeyType < USM_KEY_TYPE_LOCALIZED:
        snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
            (pysnmpUsmKeyEntry.name + (4,) + tblIdx1, masterPrivKey),
            snmpEngine=snmpEngine
        )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (pysnmpUsmSecretEntry.name + (4,) + tblIdx2, 'destroy'),
         snmpEngine=snmpEngine
    )

    # Commit plain-text pass-phrases if we have them

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (pysnmpUsmSecretEntry.name + (4,) + tblIdx2, 'createAndGo'),
        snmpEngine=snmpEngine
    )

    if authKeyType < USM_KEY_TYPE_MASTER:
        snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
            (pysnmpUsmSecretEntry.name + (1,) + tblIdx2, userName),
            (pysnmpUsmSecretEntry.name + (2,) + tblIdx2, authKey),
            snmpEngine=snmpEngine
        )

    if privKeyType < USM_KEY_TYPE_MASTER:
        snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
            (pysnmpUsmSecretEntry.name + (1,) + tblIdx2, userName),
            (pysnmpUsmSecretEntry.name + (3,) + tblIdx2, privKey),
            snmpEngine=snmpEngine
        )

    debug.logger & debug.FLAG_SM and debug.logger(
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
              securityEngineId=None):
    (securityEngineId, usmUserEntry, tblIdx1, pysnmpUsmSecretEntry,
     tblIdx2) = __cookV3UserInfo(snmpEngine, userName, securityEngineId)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (usmUserEntry.name + (13,) + tblIdx1, 'destroy'),
        snmpEngine=snmpEngine
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (pysnmpUsmSecretEntry.name + (4,) + tblIdx2, 'destroy'),
        snmpEngine=snmpEngine
    )

    debug.logger & debug.FLAG_SM and debug.logger(
        'delV3User: deleted table entries by index '
        'userName "%s" securityEngineId '
        '"%s"' % (
            userName,
            securityEngineId.prettyPrint()))

    # Drop all derived rows

    def _cbFun(varBinds, **context):
        name, val = varBinds[0]

        if exval.endOfMib.isSameTypeWith(val):
            context['user']['varBinds'] = ()

        elif not (exval.noSuchInstance.isSameTypeWith(val) or
                  exval.noSuchObject.isSameTypeWith(val)):
            context['user']['varBinds'] = varBinds

        elif varBinds[0][0][:len(initialVarBinds[0][0])] != initialVarBinds[0][0]:
            context['user']['varBinds'] = ()

        else:
            delV3User(snmpEngine, varBinds[1][1], varBinds[0][1])
            context['user']['varBinds'] = initialVarBinds

    varBinds = initialVarBinds = (
        (usmUserEntry.name + (1,), None),  # usmUserEngineID
        (usmUserEntry.name + (2,), None),  # usmUserName
        (usmUserEntry.name + (4,), None)  # usmUserCloneFrom
    )

    user = {'varBinds': varBinds}

    while user['varBinds']:
        snmpEngine.msgAndPduDsp.mibInstrumController.readNextMibObjects(
            *user['varBinds'], snmpEngine=snmpEngine, user=user, cbFun=_cbFun
        )


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

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpTargetParamsEntry.name + (7,) + tblIdx, 'destroy'),
        snmpEngine=snmpEngine
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpTargetParamsEntry.name + (1,) + tblIdx, name),
        (snmpTargetParamsEntry.name + (2,) + tblIdx, mpModel),
        (snmpTargetParamsEntry.name + (3,) + tblIdx, securityModel),
        (snmpTargetParamsEntry.name + (4,) + tblIdx, securityName),
        (snmpTargetParamsEntry.name + (5,) + tblIdx, securityLevel),
        (snmpTargetParamsEntry.name + (7,) + tblIdx, 'createAndGo'),
        snmpEngine=snmpEngine
    )


def delTargetParams(snmpEngine, name):
    snmpTargetParamsEntry, tblIdx = __cookTargetParamsInfo(snmpEngine, name)
    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpTargetParamsEntry.name + (7,) + tblIdx, 'destroy'),
        snmpEngine=snmpEngine
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

    (snmpTargetAddrEntry,
     snmpSourceAddrEntry,
     tblIdx) = __cookTargetAddrInfo(snmpEngine, addrName)

    if transportDomain[:len(SNMP_UDP_DOMAIN)] == SNMP_UDP_DOMAIN:
        SnmpUDPAddress, = mibBuilder.importSymbols('SNMPv2-TM', 'SnmpUDPAddress')
        transportAddress = SnmpUDPAddress(transportAddress)

        if sourceAddress is None:
            sourceAddress = ('0.0.0.0', 0)

        sourceAddress = SnmpUDPAddress(sourceAddress)

    elif transportDomain[:len(SNMP_UDP6_DOMAIN)] == SNMP_UDP6_DOMAIN:
        TransportAddressIPv6, = mibBuilder.importSymbols('TRANSPORT-ADDRESS-MIB', 'TransportAddressIPv6')
        transportAddress = TransportAddressIPv6(transportAddress)

        if sourceAddress is None:
            sourceAddress = ('::', 0)

        sourceAddress = TransportAddressIPv6(sourceAddress)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpTargetAddrEntry.name + (9,) + tblIdx, 'destroy'),
        snmpEngine=snmpEngine
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpTargetAddrEntry.name + (1,) + tblIdx, addrName),
        (snmpTargetAddrEntry.name + (2,) + tblIdx, transportDomain),
        (snmpTargetAddrEntry.name + (3,) + tblIdx, transportAddress),
        (snmpTargetAddrEntry.name + (4,) + tblIdx, timeout),
        (snmpTargetAddrEntry.name + (5,) + tblIdx, retryCount),
        (snmpTargetAddrEntry.name + (6,) + tblIdx, tagList),
        (snmpTargetAddrEntry.name + (7,) + tblIdx, params),
        (snmpSourceAddrEntry.name + (1,) + tblIdx, sourceAddress),
        (snmpTargetAddrEntry.name + (9,) + tblIdx, 'createAndGo'),
        snmpEngine=snmpEngine
    )


def delTargetAddr(snmpEngine, addrName):
    (snmpTargetAddrEntry, snmpSourceAddrEntry,
     tblIdx) = __cookTargetAddrInfo(snmpEngine, addrName)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpTargetAddrEntry.name + (9,) + tblIdx, 'destroy'),
        snmpEngine=snmpEngine
    )


def addTransport(snmpEngine, transportDomain, transport):
    if snmpEngine.transportDispatcher:
        if not transport.isCompatibleWithDispatcher(snmpEngine.transportDispatcher):
            raise error.PySnmpError(
                'Transport %r is not compatible with dispatcher %r' % (
                    transport, snmpEngine.transportDispatcher))

    else:
        snmpEngine.registerTransportDispatcher(
            transport.PROTO_TRANSPORT_DISPATCHER()
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
            automaticTransportDispatcher=automaticTransportDispatcher)

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

    vacmContextEntry, = mibBuilder.importSymbols(
        'SNMP-VIEW-BASED-ACM-MIB', 'vacmContextEntry')

    tblIdx = vacmContextEntry.getInstIdFromIndices(contextName)

    return vacmContextEntry, tblIdx


def addContext(snmpEngine, contextName):
    vacmContextEntry, tblIdx = __cookVacmContextInfo(snmpEngine, contextName)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (vacmContextEntry.name + (2,) + tblIdx, 'destroy'),
        snmpEngine=snmpEngine
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (vacmContextEntry.name + (1,) + tblIdx, contextName),
        (vacmContextEntry.name + (2,) + tblIdx, 'createAndGo'),
        snmpEngine=snmpEngine
    )


def delContext(snmpEngine, contextName):
    vacmContextEntry, tblIdx = __cookVacmContextInfo(snmpEngine, contextName)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (vacmContextEntry.name + (2,) + tblIdx, 'destroy'),
        snmpEngine=snmpEngine
    )


def __cookVacmGroupInfo(snmpEngine, securityModel, securityName):
    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    vacmSecurityToGroupEntry, = mibBuilder.importSymbols(
        'SNMP-VIEW-BASED-ACM-MIB', 'vacmSecurityToGroupEntry')

    tblIdx = vacmSecurityToGroupEntry.getInstIdFromIndices(
        securityModel, securityName)

    return vacmSecurityToGroupEntry, tblIdx


def addVacmGroup(snmpEngine, groupName, securityModel, securityName):
    (vacmSecurityToGroupEntry,
     tblIdx) = __cookVacmGroupInfo(snmpEngine, securityModel, securityName)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (vacmSecurityToGroupEntry.name + (5,) + tblIdx, 'destroy'),
        snmpEngine=snmpEngine
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (vacmSecurityToGroupEntry.name + (1,) + tblIdx, securityModel),
        (vacmSecurityToGroupEntry.name + (2,) + tblIdx, securityName),
        (vacmSecurityToGroupEntry.name + (3,) + tblIdx, groupName),
        (vacmSecurityToGroupEntry.name + (5,) + tblIdx, 'createAndGo'),
        snmpEngine=snmpEngine
    )


def delVacmGroup(snmpEngine, securityModel, securityName):
    vacmSecurityToGroupEntry, tblIdx = __cookVacmGroupInfo(
        snmpEngine, securityModel, securityName
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (vacmSecurityToGroupEntry.name + (5,) + tblIdx, 'destroy'),
        snmpEngine=snmpEngine
    )


def __cookVacmAccessInfo(snmpEngine, groupName, contextName, securityModel,
                         securityLevel):
    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    vacmAccessEntry, = mibBuilder.importSymbols(
        'SNMP-VIEW-BASED-ACM-MIB', 'vacmAccessEntry')

    tblIdx = vacmAccessEntry.getInstIdFromIndices(
        groupName, contextName, securityModel, securityLevel)

    return vacmAccessEntry, tblIdx


def addVacmAccess(snmpEngine, groupName, contextPrefix, securityModel,
                  securityLevel, contextMatch, readView, writeView, notifyView):
    vacmAccessEntry, tblIdx = __cookVacmAccessInfo(
        snmpEngine, groupName, contextPrefix, securityModel,
        securityLevel)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (vacmAccessEntry.name + (9,) + tblIdx, 'destroy'),
        snmpEngine=snmpEngine
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (vacmAccessEntry.name + (1,) + tblIdx, contextPrefix),
        (vacmAccessEntry.name + (2,) + tblIdx, securityModel),
        (vacmAccessEntry.name + (3,) + tblIdx, securityLevel),
        (vacmAccessEntry.name + (4,) + tblIdx, contextMatch),
        (vacmAccessEntry.name + (5,) + tblIdx, readView),
        (vacmAccessEntry.name + (6,) + tblIdx, writeView),
        (vacmAccessEntry.name + (7,) + tblIdx, notifyView),
        (vacmAccessEntry.name + (9,) + tblIdx, 'createAndGo'),
        snmpEngine=snmpEngine
    )


def delVacmAccess(snmpEngine, groupName, contextPrefix, securityModel,
                  securityLevel):

    vacmAccessEntry, tblIdx = __cookVacmAccessInfo(
        snmpEngine, groupName, contextPrefix, securityModel, securityLevel)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (vacmAccessEntry.name + (9,) + tblIdx, 'destroy'),
        snmpEngine=snmpEngine
    )


def __cookVacmViewInfo(snmpEngine, viewName, subTree):
    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    vacmViewTreeFamilyEntry, = mibBuilder.importSymbols(
        'SNMP-VIEW-BASED-ACM-MIB', 'vacmViewTreeFamilyEntry')

    tblIdx = vacmViewTreeFamilyEntry.getInstIdFromIndices(viewName, subTree)

    return vacmViewTreeFamilyEntry, tblIdx


def addVacmView(snmpEngine, viewName, viewType, subTree, subTreeMask):

    # Allow bitmask specification in form of an OID
    if rfc1902.OctetString('.').asOctets() in rfc1902.OctetString(subTreeMask):
        subTreeMask = rfc1902.ObjectIdentifier(subTreeMask)

    if isinstance(subTreeMask, rfc1902.ObjectIdentifier):
        subTreeMask = tuple(subTreeMask)
        if len(subTreeMask) < len(subTree):
            subTreeMask += (1,) * (len(subTree) - len(subTreeMask))

        subTreeMask = rfc1902.OctetString.fromBinaryString(
            ''.join(str(x) for x in subTreeMask))

    vacmViewTreeFamilyEntry, tblIdx = __cookVacmViewInfo(
        snmpEngine, viewName, subTree)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (vacmViewTreeFamilyEntry.name + (6,) + tblIdx, 'destroy'),
        snmpEngine=snmpEngine
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (vacmViewTreeFamilyEntry.name + (1,) + tblIdx, viewName),
        (vacmViewTreeFamilyEntry.name + (2,) + tblIdx, subTree),
        (vacmViewTreeFamilyEntry.name + (3,) + tblIdx, subTreeMask),
        (vacmViewTreeFamilyEntry.name + (4,) + tblIdx, viewType),
        (vacmViewTreeFamilyEntry.name + (6,) + tblIdx, 'createAndGo'),
        snmpEngine=snmpEngine
    )


def delVacmView(snmpEngine, viewName, subTree):
    vacmViewTreeFamilyEntry, tblIdx = __cookVacmViewInfo(
        snmpEngine, viewName, subTree)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (vacmViewTreeFamilyEntry.name + (6,) + tblIdx, 'destroy'),
        snmpEngine=snmpEngine
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
     notifyView) = __cookVacmUserInfo(
        snmpEngine, securityModel, securityName, securityLevel)

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
     notifyView) = __cookVacmUserInfo(
        snmpEngine, securityModel, securityName, securityLevel)

    delContext(snmpEngine, contextName)
    delVacmGroup(snmpEngine, securityModel, securityName)
    delVacmAccess(snmpEngine, groupName, contextName,
                  securityModel, securityLevel)

    if readSubTree:
        delVacmView(snmpEngine, readView, readSubTree)

    if writeSubTree:
        delVacmView(snmpEngine, writeView, writeSubTree)

    if notifySubTree:
        delVacmView(snmpEngine, notifyView, notifySubTree)

# Notification target setup

def __cookNotificationTargetInfo(snmpEngine, notificationName, paramsName,
                                 filterSubtree=None):

    mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    snmpNotifyEntry, = mibBuilder.importSymbols(
        'SNMP-NOTIFICATION-MIB', 'snmpNotifyEntry')

    tblIdx1 = snmpNotifyEntry.getInstIdFromIndices(notificationName)

    snmpNotifyFilterProfileEntry, = mibBuilder.importSymbols(
        'SNMP-NOTIFICATION-MIB', 'snmpNotifyFilterProfileEntry')

    tblIdx2 = snmpNotifyFilterProfileEntry.getInstIdFromIndices(paramsName)

    profileName = '%s-filter' % hash(notificationName)

    if filterSubtree:
        snmpNotifyFilterEntry, = mibBuilder.importSymbols(
            'SNMP-NOTIFICATION-MIB', 'snmpNotifyFilterEntry')

        tblIdx3 = snmpNotifyFilterEntry.getInstIdFromIndices(
            profileName, filterSubtree)

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
     tblIdx3) = __cookNotificationTargetInfo(
        snmpEngine, notificationName, paramsName, filterSubtree)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpNotifyEntry.name + (5,) + tblIdx1, 'destroy'),
        snmpEngine=snmpEngine
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpNotifyEntry.name + (2,) + tblIdx1, transportTag),
        (snmpNotifyEntry.name + (3,) + tblIdx1, notifyType),
        (snmpNotifyEntry.name + (5,) + tblIdx1, 'createAndGo'),
        snmpEngine=snmpEngine
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpNotifyFilterProfileEntry.name + (3,) + tblIdx2, 'destroy'),
        snmpEngine=snmpEngine
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpNotifyFilterProfileEntry.name + (1,) + tblIdx2, profileName),
        (snmpNotifyFilterProfileEntry.name + (3,) + tblIdx2, 'createAndGo'),
        snmpEngine=snmpEngine
    )

    if not snmpNotifyFilterEntry:
        return

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpNotifyFilterEntry.name + (5,) + tblIdx3, 'destroy'),
        snmpEngine=snmpEngine
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpNotifyFilterEntry.name + (1,) + tblIdx3, filterSubtree),
        (snmpNotifyFilterEntry.name + (2,) + tblIdx3, filterMask),
        (snmpNotifyFilterEntry.name + (3,) + tblIdx3, filterType),
        (snmpNotifyFilterEntry.name + (5,) + tblIdx3, 'createAndGo'),
        snmpEngine=snmpEngine
    )


def delNotificationTarget(snmpEngine, notificationName, paramsName,
                          filterSubtree=None):
    (snmpNotifyEntry, tblIdx1, snmpNotifyFilterProfileEntry,
     tblIdx2, profileName, snmpNotifyFilterEntry,
     tblIdx3) = __cookNotificationTargetInfo(
        snmpEngine, notificationName, paramsName, filterSubtree)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpNotifyEntry.name + (5,) + tblIdx1, 'destroy'),
        snmpEngine=snmpEngine
    )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpNotifyFilterProfileEntry.name + (3,) + tblIdx2, 'destroy'),
        snmpEngine=snmpEngine
    )

    if not snmpNotifyFilterEntry:
        return

    snmpEngine.msgAndPduDsp.mibInstrumController.writeMibObjects(
        (snmpNotifyFilterEntry.name + (5,) + tblIdx3, 'destroy'),
        snmpEngine=snmpEngine
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
