# Initial SNMP engine configuration functions. During further operation,
# SNMP engine might be configured remotely (through SNMP).
import string
from pysnmp.carrier.asynsock import dispatch
from pysnmp.carrier.asynsock.dgram import udp
try:
    from pysnmp.carrier.asynsock.dgram import unix
    snmpLocalDomain = unix.snmpLocalDomain
except ImportError: # UNIX-specific -- may not be always available
    pass
from pysnmp.proto import rfc3412
from pysnmp.proto.secmod.rfc3414 import localkey
from pysnmp.entity import engine
from pysnmp.proto.secmod.rfc3414.auth import hmacmd5, hmacsha, noauth
from pysnmp.proto.secmod.rfc3414.priv import des, nopriv
from pysnmp.proto.secmod.rfc3826.priv import aes
from pysnmp.smi.error import NotWritableError
from pysnmp import error

# A shortcut to popular constants

# Transports
snmpUDPDomain = udp.snmpUDPDomain

# Auth protocol
usmHMACMD5AuthProtocol = hmacmd5.HmacMd5.serviceID
usmHMACSHAAuthProtocol = hmacsha.HmacSha.serviceID
usmNoAuthProtocol = noauth.NoAuth.serviceID

# Privacy protocol
usmDESPrivProtocol = des.Des.serviceID
usmAesCfb128Protocol = aes.Aes.serviceID
usmNoPrivProtocol = nopriv.NoPriv.serviceID

def __cookV1SystemInfo(snmpEngine, securityName):
    snmpEngineID, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineID')

    snmpCommunityEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-COMMUNITY-MIB', 'snmpCommunityEntry')
    tblIdx = snmpCommunityEntry.getInstIdFromIndices(securityName)
    return snmpCommunityEntry, tblIdx, snmpEngineID
    
def addV1System(snmpEngine, securityName, communityName,
                contextEngineId=None, contextName=None,
                transportTag=None):
    snmpCommunityEntry, tblIdx, snmpEngineID = __cookV1SystemInfo(
        snmpEngine, securityName
        )

    if contextEngineId is None:
        contextEngineId = snmpEngineID.syntax
    if contextName is not None:
        contextName = communityName

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpCommunityEntry.name + (8,) + tblIdx, 'destroy'),)
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpCommunityEntry.name + (8,) + tblIdx, 'createAndGo'),
         (snmpCommunityEntry.name + (2,) + tblIdx, communityName),
         (snmpCommunityEntry.name + (3,) + tblIdx, securityName),
         (snmpCommunityEntry.name + (4,) + tblIdx, contextEngineId),
         (snmpCommunityEntry.name + (5,) + tblIdx, contextName),
         (snmpCommunityEntry.name + (6,) + tblIdx, transportTag),
         (snmpCommunityEntry.name + (7,) + tblIdx, 'nonVolatile'))
        )

def delV1System(snmpEngine, securityName):
    snmpCommunityEntry, tblIdx, snmpEngineID = __cookV1SystemInfo(
        snmpEngine, securityName
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpCommunityEntry.name + (8,) + tblIdx, 'destroy'),)
        )

def __cookV3UserInfo(snmpEngine, securityName, contextEngineId):
    if contextEngineId is None:
        snmpEngineID, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineID')
        snmpEngineID = snmpEngineID.syntax
    else:
        snmpEngineID = contextEngineId

    usmUserEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-USER-BASED-SM-MIB', 'usmUserEntry')
    tblIdx1 = usmUserEntry.getInstIdFromIndices(
        snmpEngineID, securityName
        )

    pysnmpUsmSecretEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('PYSNMP-USM-MIB', 'pysnmpUsmSecretEntry')
    tblIdx2 = pysnmpUsmSecretEntry.getInstIdFromIndices(securityName)

    return snmpEngineID, usmUserEntry, tblIdx1, pysnmpUsmSecretEntry, tblIdx2

def addV3User(snmpEngine, securityName,
              authProtocol=usmNoAuthProtocol, authKey=None,
              privProtocol=usmNoPrivProtocol, privKey=None,
              contextEngineId=None):
    ( snmpEngineID, usmUserEntry, tblIdx1,
      pysnmpUsmSecretEntry, tblIdx2 ) = __cookV3UserInfo(
        snmpEngine, securityName, contextEngineId
        )

    # Load augmenting table before creating new row in base one
    pysnmpUsmKeyEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('PYSNMP-USM-MIB', 'pysnmpUsmKeyEntry')

    # Load clone-from (may not be needed)
    zeroDotZero, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMPv2-SMI', 'zeroDotZero')

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((usmUserEntry.name + (13,) + tblIdx1, 'destroy'),)
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((usmUserEntry.name + (13,) + tblIdx1, 'createAndGo'),
         (usmUserEntry.name + (3,) + tblIdx1, securityName),
         (usmUserEntry.name + (4,) + tblIdx1, zeroDotZero.name),
         (usmUserEntry.name + (5,) + tblIdx1, authProtocol),
         (usmUserEntry.name + (8,) + tblIdx1, privProtocol))
        )

    # Localize keys
    if authProtocol == usmHMACMD5AuthProtocol:
        hashedAuthPassphrase = localkey.hashPassphraseMD5(
            authKey and authKey or ''
            )
        localAuthKey = localkey.localizeKeyMD5(
            hashedAuthPassphrase, snmpEngineID
            )
    elif authProtocol == usmHMACSHAAuthProtocol:
        hashedAuthPassphrase = localkey.hashPassphraseSHA(
            authKey and authKey or ''
            )
        localAuthKey = localkey.localizeKeySHA(
            hashedAuthPassphrase, snmpEngineID
            )
    elif authProtocol == usmNoAuthProtocol:
        hashedAuthPassphrase = localAuthKey = None
    else:
        raise error.PySnmpError('Unknown auth protocol %s' % (authProtocol,))

    if privProtocol == usmDESPrivProtocol or \
       privProtocol == usmAesCfb128Protocol:
        if authProtocol == usmHMACMD5AuthProtocol:
            hashedPrivPassphrase = localkey.hashPassphraseMD5(
                privKey and privKey or ''
                )
            localPrivKey = localkey.localizeKeyMD5(
                hashedPrivPassphrase, snmpEngineID
                )
        elif authProtocol == usmHMACSHAAuthProtocol:
            hashedPrivPassphrase = localkey.hashPassphraseSHA(
                privKey and privKey or ''
                )
            localPrivKey = localkey.localizeKeySHA(
                hashedPrivPassphrase, snmpEngineID
                )
        else:
            raise error.PySnmpError(
                'Unknown auth protocol %s' % (authProtocol,)
                )
    elif privProtocol == usmNoPrivProtocol:
        hashedPrivPassphrase = localPrivKey = None
    else:
        raise error.PySnmpError(
            'Unknown priv protocol %s' % (privProtocol,)
            )

    # Commit localized keys
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((pysnmpUsmKeyEntry.name + (1,) + tblIdx1, localAuthKey),
         (pysnmpUsmKeyEntry.name + (2,) + tblIdx1, localPrivKey),
         (pysnmpUsmKeyEntry.name + (3,) + tblIdx1, hashedAuthPassphrase),
         (pysnmpUsmKeyEntry.name + (4,) + tblIdx1, hashedPrivPassphrase))
        )

    # Commit passphrases

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((pysnmpUsmSecretEntry.name + (4,) + tblIdx2, 'destroy'),)
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((pysnmpUsmSecretEntry.name + (4,) + tblIdx2, 'createAndGo'),
         (pysnmpUsmSecretEntry.name + (2,) + tblIdx2, authKey),
         (pysnmpUsmSecretEntry.name + (3,) + tblIdx2, privKey),)
        )

def delV3User(snmpEngine, securityName, contextEngineId=None):
    ( snmpEngineID, usmUserEntry, tblIdx1,
      pysnmpUsmSecretEntry, tblIdx2 ) = __cookV3UserInfo(
        snmpEngine, securityName, contextEngineId
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((usmUserEntry.name + (13,) + tblIdx1, 'destroy'),)
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((pysnmpUsmSecretEntry.name + (4,) + tblIdx2, 'destroy'),)
        )

def __cookTargetParamsInfo(snmpEngine, name):
    snmpTargetParamsEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-TARGET-MIB', 'snmpTargetParamsEntry')
    tblIdx = snmpTargetParamsEntry.getInstIdFromIndices(name)
    return snmpTargetParamsEntry, tblIdx
    
def addTargetParams(
    snmpEngine,
    name,
    securityName,
    securityLevel,
    mpModel=3  # 0 == SNMPv1, 1 == SNMPv2c, 3 == SNMPv3
    ):
    if mpModel == 0:
        securityModel = 1
    elif mpModel == 1 or mpModel == 2:
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
        ((snmpTargetParamsEntry.name + (7,) + tblIdx, 'createAndGo'),
         (snmpTargetParamsEntry.name + (1,) + tblIdx, name),
         (snmpTargetParamsEntry.name + (2,) + tblIdx, mpModel),
         (snmpTargetParamsEntry.name + (3,) + tblIdx, securityModel),
         (snmpTargetParamsEntry.name + (4,) + tblIdx, securityName),
         (snmpTargetParamsEntry.name + (5,) + tblIdx, securityLevel))
        )

def delTargetParams(snmpEngine, name):
    snmpTargetParamsEntry, tblIdx = __cookTargetParamsInfo(
        snmpEngine, name
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpTargetParamsEntry.name + (7,) + tblIdx, 'destroy'),)
        )

def __cookTargetAddrInfo(snmpEngine, addrName):
    snmpTargetAddrEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-TARGET-MIB', 'snmpTargetAddrEntry')
    tblIdx = snmpTargetAddrEntry.getInstIdFromIndices(addrName)
    return snmpTargetAddrEntry, tblIdx

def addTargetAddr(
    snmpEngine,
    addrName,
    transportDomain,    
    transportAddress,
    params,
    timeout=None,
    retryCount=None,
    tagList=''
    ):
    snmpTargetAddrEntry, tblIdx = __cookTargetAddrInfo(
        snmpEngine, addrName
        )
    
    if transportDomain == snmpUDPDomain:
        SnmpUDPAddress, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMPv2-TM', 'SnmpUDPAddress')
        transportAddress = SnmpUDPAddress(transportAddress)

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpTargetAddrEntry.name + (9,) + tblIdx, 'destroy'),)
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpTargetAddrEntry.name + (9,) + tblIdx, 'createAndGo'),
        (snmpTargetAddrEntry.name + (1,) + tblIdx, addrName),
        (snmpTargetAddrEntry.name + (2,) + tblIdx, transportDomain),
        (snmpTargetAddrEntry.name + (3,) + tblIdx, transportAddress),
        (snmpTargetAddrEntry.name + (4,) + tblIdx, timeout),
        (snmpTargetAddrEntry.name + (5,) + tblIdx, retryCount),
         # XXX
        (snmpTargetAddrEntry.name + (6,) + tblIdx,'%s %s'%(addrName,tagList)),
        (snmpTargetAddrEntry.name + (7,) + tblIdx, params),)
        )

def delTargetAddr(snmpEngine, addrName):
    snmpTargetAddrEntry, tblIdx = __cookTargetAddrInfo(
        snmpEngine, addrName
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpTargetAddrEntry.name + (9,) + tblIdx, 'destroy'),)
        )

def addSocketTransport(snmpEngine, transportDomain, transport):
    """Add transport object to socket dispatcher of snmpEngine"""
    if not snmpEngine.transportDispatcher:
        snmpEngine.registerTransportDispatcher(dispatch.AsynsockDispatcher())
    snmpEngine.transportDispatcher.registerTransport(
        transportDomain, transport
        )

def delSocketTransport(snmpEngine, transportDomain):
    """Unregister transport object at socket dispatcher of snmpEngine"""
    if not snmpEngine.transportDispatcher:
        return
    snmpEngine.transportDispatcher.unregisterTransport(
        transportDomain
        )
    snmpEngine.unregisterTransportDispatcher()

# VACM shortcuts

def addContext(snmpEngine, contextName):
    vacmContextEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
        'SNMP-VIEW-BASED-ACM-MIB', 'vacmContextEntry'
        )
    tblIdx = vacmContextEntry.getInstIdFromIndices(contextName)
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmContextEntry.name + (1,) + tblIdx, contextName),)
        )

def __cookVacmGroupInfo(snmpEngine, securityModel, securityName):
    vacmSecurityToGroupEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
        'SNMP-VIEW-BASED-ACM-MIB', 'vacmSecurityToGroupEntry'
        )
    tblIdx = vacmSecurityToGroupEntry.getInstIdFromIndices(
        securityModel, securityName
        )
    return vacmSecurityToGroupEntry, tblIdx

def addVacmGroup(snmpEngine, groupName, securityModel, securityName):
    vacmSecurityToGroupEntry, tblIdx = __cookVacmGroupInfo(
        snmpEngine, securityModel, securityName
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmSecurityToGroupEntry.name + (5,) + tblIdx, 'destroy'),)
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmSecurityToGroupEntry.name + (5,) + tblIdx, 'createAndGo'),
        (vacmSecurityToGroupEntry.name + (1,) + tblIdx, securityModel),
        (vacmSecurityToGroupEntry.name + (2,) + tblIdx, securityName),
        (vacmSecurityToGroupEntry.name + (3,) + tblIdx, groupName),)
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
    vacmAccessEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
        'SNMP-VIEW-BASED-ACM-MIB', 'vacmAccessEntry'
        )
    tblIdx = vacmAccessEntry.getInstIdFromIndices(
        groupName, contextName, securityModel, securityLevel
        )
    return vacmAccessEntry, tblIdx

def addVacmAccess(snmpEngine, groupName, contextName, securityModel,
                  securityLevel, prefix, readView, writeView, notifyView):
    vacmAccessEntry, tblIdx = __cookVacmAccessInfo(
        snmpEngine, groupName, contextName, securityModel, securityLevel
        )

    addContext(snmpEngine, contextName) # this is leaky
    
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmAccessEntry.name + (9,) + tblIdx, 'destroy'),)
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmAccessEntry.name + (9,) + tblIdx, 'createAndGo'),
        (vacmAccessEntry.name + (1,) + tblIdx, contextName),
        (vacmAccessEntry.name + (2,) + tblIdx, securityModel),
        (vacmAccessEntry.name + (3,) + tblIdx, securityLevel),
        (vacmAccessEntry.name + (4,) + tblIdx, prefix),
        (vacmAccessEntry.name + (5,) + tblIdx, readView),
        (vacmAccessEntry.name + (6,) + tblIdx, writeView),
        (vacmAccessEntry.name + (7,) + tblIdx, notifyView),)
        )

def delVacmAccess(snmpEngine, groupName, contextName, securityModel,
                  securityLevel):
    vacmAccessEntry, tblIdx = __cookVacmAccessInfo(
        snmpEngine, groupName, contextName, securityModel, securityLevel
        )    
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmAccessEntry.name + (9,) + tblIdx, 'destroy'),)
        )

def __cookVacmViewInfo(snmpEngine, viewName, subTree):
    vacmViewTreeFamilyEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
        'SNMP-VIEW-BASED-ACM-MIB', 'vacmViewTreeFamilyEntry'
        )
    tblIdx = vacmViewTreeFamilyEntry.getInstIdFromIndices(
        viewName, subTree
        )
    return vacmViewTreeFamilyEntry, tblIdx

def addVacmView(snmpEngine, viewName, viewType, subTree, mask):
    vacmViewTreeFamilyEntry, tblIdx = __cookVacmViewInfo(
        snmpEngine, viewName, subTree
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmViewTreeFamilyEntry.name + (6,) + tblIdx, 'destroy'),)
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmViewTreeFamilyEntry.name + (6,) + tblIdx, 'createAndGo'),
         (vacmViewTreeFamilyEntry.name + (1,) + tblIdx, viewName),
         (vacmViewTreeFamilyEntry.name + (2,) + tblIdx, subTree),
         (vacmViewTreeFamilyEntry.name + (3,) + tblIdx, mask),
         (vacmViewTreeFamilyEntry.name + (4,) + tblIdx, viewType),)
        )

def delVacmView(snmpEngine, viewName, subTree):
    vacmViewTreeFamilyEntry, tblIdx = __cookVacmViewInfo(
        snmpEngine, viewName, subTree
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((vacmViewTreeFamilyEntry.name + (6,) + tblIdx, 'destroy'),)
        )

# VACM simplicity wrappers

def __cookVacmUserInfo(snmpEngine, securityModel, securityName, securityLevel):
    groupName = 'v-%s-%d' % (hash(securityName), securityModel)
    SnmpSecurityLevel, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-FRAMEWORK-MIB', 'SnmpSecurityLevel')
    securityLevel = SnmpSecurityLevel(securityLevel)
    return ( groupName, securityLevel,
             'r' + groupName, 'w' + groupName, 'n' + groupName )

def addVacmUser(snmpEngine, securityModel, securityName, securityLevel,
                readSubTree=(), writeSubTree=(), notifySubTree=()):
    ( groupName, securityLevel,
      readView, writeView, notifyView ) = __cookVacmUserInfo(
        snmpEngine, securityModel, securityName, securityLevel,
        )
    addVacmGroup(
        snmpEngine, groupName, securityModel, securityName
        )
    addVacmAccess(
        snmpEngine, groupName, '', securityModel, securityLevel, 1,
        readView, writeView, notifyView
        )
    if readSubTree:
        addVacmView(
            snmpEngine, readView, "included", readSubTree, '',
            )
    if writeSubTree:
        addVacmView(
            snmpEngine, writeView, "included", writeSubTree, '',
            )
    if notifySubTree:
        addVacmView(
            snmpEngine, notifyView, "included", notifySubTree, '',
            )

def delVacmUser(snmpEngine, securityModel, securityName, securityLevel,
                readSubTree=(), writeSubTree=(), notifySubTree=()):
    ( groupName, securityLevel,
      readView, writeView, notifyView ) = __cookVacmUserInfo(
        snmpEngine, securityModel, securityName, securityLevel,
        )
    delVacmGroup(
        snmpEngine, securityModel, securityName
        )
    delVacmAccess(
        snmpEngine, groupName, '', securityModel, securityLevel
        )
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

def addRoUser(snmpEngine, securityModel, securityName, securityLevel, subTree):
    addVacmUser(
        snmpEngine, securityModel, securityName, securityLevel, subTree
        )

def delRoUser(snmpEngine, securityModel, securityName, securityLevel, subTree):
    delVacmUser(
        snmpEngine, securityModel, securityName, securityLevel, subTree
        )

def addRwUser(snmpEngine, securityModel, securityName, securityLevel, subTree):
    addVacmUser(
        snmpEngine, securityModel, securityName, securityLevel,
        subTree, subTree
        )

def delRwUser(snmpEngine, securityModel, securityName, securityLevel, subTree):
    delVacmUser(
        snmpEngine, securityModel, securityName, securityLevel,
        subTree, subTree
        )

def addTrapUser(snmpEngine,securityModel,securityName,securityLevel,subTree):
    addVacmUser(
        snmpEngine, securityModel, securityName, securityLevel,
        (), (), subTree,
        )

def delTrapUser(snmpEngine,securityModel,securityName,securityLevel,subTree):
    delVacmUser(
        snmpEngine, securityModel, securityName, securityLevel,
        (), (), subTree,
        )

# Notification target setup

def __cookNotificationTargetInfo(snmpEngine, notificationName, paramsName,
                                 filterSubtree=None):
    snmpNotifyEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-NOTIFICATION-MIB', 'snmpNotifyEntry')
    tblIdx1 = snmpNotifyEntry.getInstIdFromIndices(
        notificationName
        )

    snmpNotifyFilterProfileEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-NOTIFICATION-MIB', 'snmpNotifyFilterProfileEntry')
    tblIdx2 = snmpNotifyFilterProfileEntry.getInstIdFromIndices(
        paramsName
        )

    profileName = '%s-filter' % hash(notificationName)
    
    if filterSubtree:
        snmpNotifyFilterEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-NOTIFICATION-MIB', 'snmpNotifyFilterEntry')
        tblIdx3 = snmpNotifyFilterEntry.getInstIdFromIndices(
            profileName, filterSubtree
            )
    else:
        snmpNotifyFilterEntry = tblIdx3 = None

    return ( snmpNotifyEntry, tblIdx1,
             snmpNotifyFilterProfileEntry, tblIdx2, profileName,
             snmpNotifyFilterEntry, tblIdx3 )

def addNotificationTarget(snmpEngine, notificationName, paramsName,
                          transportTag, notifyType=None, filterSubtree=None,
                          filterMask=None, filterType=None):
    ( snmpNotifyEntry, tblIdx1,
      snmpNotifyFilterProfileEntry, tblIdx2, profileName,
      snmpNotifyFilterEntry, tblIdx3 ) = __cookNotificationTargetInfo(
        snmpEngine, notificationName, paramsName, filterSubtree
        )
    
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyEntry.name + (5,) + tblIdx1, 'destroy'),)
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyEntry.name + (5,) + tblIdx1, 'createAndGo'),
         (snmpNotifyEntry.name + (2,) + tblIdx1, transportTag),
         (snmpNotifyEntry.name + (3,) + tblIdx1, notifyType),)
        )

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyFilterProfileEntry.name + (3,) + tblIdx2, 'destroy'),)
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyFilterProfileEntry.name + (3,) + tblIdx2, 'createAndGo'),
         (snmpNotifyFilterProfileEntry.name + (1,) + tblIdx2, profileName),)
        )

    if not snmpNotifyFilterEntry:
        return

    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyFilterEntry.name + (5,) + tblIdx3, 'destroy'),)
        )    
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyFilterEntry.name + (5,) + tblIdx3, 'createAndGo'),
         (snmpNotifyFilterEntry.name + (1,) + tblIdx3, filterSubtree),
         (snmpNotifyFilterEntry.name + (2,) + tblIdx3, filterMask),
         (snmpNotifyFilterEntry.name + (3,) + tblIdx3, filterType),)
        )

def delNotificationTarget(snmpEngine, notificationName, paramsName,
                          filterSubtree=None):
    ( snmpNotifyEntry, tblIdx1,
      snmpNotifyFilterProfileEntry, tblIdx2, profileName,
      snmpNotifyFilterEntry, tblIdx3 ) = __cookNotificationTargetInfo(
        snmpEngine, notificationName, paramsName, filterSubtree
        )

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
    addVacmView(snmpEngine, "internet", "included", (1,3,6,1),"")
    addVacmView(snmpEngine, "restricted", "included", (1,3,6,1,2,1,1),"")
    addVacmView(snmpEngine, "restricted", "included", (1,3,6,1,2,1,11),"")
    addVacmView(snmpEngine, "restricted", "included", (1,3,6,1,6,3,10,2,1),"")
    addVacmView(snmpEngine, "restricted", "included", (1,3,6,1,6,3,11,2,1),"")
    addVacmView(snmpEngine, "restricted", "included", (1,3,6,1,6,3,15,1,1),"")
