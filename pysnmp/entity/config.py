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
usmNoPrivProtocol = nopriv.NoPriv.serviceID

def addV1System(snmpEngine, securityName, communityName,
                contextEngineId=None, contextName=None,
                transportTag=None):
    snmpEngineID, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineID')

    # Build entry index
    snmpCommunityEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-COMMUNITY-MIB', 'snmpCommunityEntry')
    tblIdx = snmpCommunityEntry.getInstIdFromIndices(
        snmpEngineID.syntax, securityName
        )

    if contextEngineId is None:
        contextEngineId = snmpEngineID.syntax
    if contextName is not None:
        contextName = communityName

    # Destroy&Create new row
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

def addV3User(snmpEngine, securityName,
              authProtocol=usmNoAuthProtocol, authKey=None,
              privProtocol=usmNoPrivProtocol, privKey=None,
              contextEngineId=None):
    # v3 setup
    if contextEngineId is None:
        snmpEngineID, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineID')
        snmpEngineID = snmpEngineID.syntax
    else:
        snmpEngineID = contextEngineId

    # Build entry index
    usmUserEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-USER-BASED-SM-MIB', 'usmUserEntry')
    tblIdx = usmUserEntry.getInstIdFromIndices(
        snmpEngineID, securityName
        )

    # Load augmenting table before creating new row in base one
    pysnmpUsmKeyEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('PYSNMP-USM-MIB', 'pysnmpUsmKeyEntry')

    # Load clone-from (may not be needed)
    zeroDotZero, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMPv2-SMI', 'zeroDotZero')

    # Destroy&Create new row
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((usmUserEntry.name + (13,) + tblIdx, 'destroy'),)
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((usmUserEntry.name + (13,) + tblIdx, 'createAndGo'),
         (usmUserEntry.name + (3,) + tblIdx, securityName),
         (usmUserEntry.name + (4,) + tblIdx, zeroDotZero.name),
         (usmUserEntry.name + (5,) + tblIdx, authProtocol),
         (usmUserEntry.name + (8,) + tblIdx, privProtocol))
        )

    usmUserSecurityName = usmUserEntry.getNode(
        usmUserEntry.name + (3,) + tblIdx
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

    if privProtocol == usmDESPrivProtocol:
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
        ((pysnmpUsmKeyEntry.name + (1,) + tblIdx, localAuthKey),
         (pysnmpUsmKeyEntry.name + (2,) + tblIdx, localPrivKey),
         (pysnmpUsmKeyEntry.name + (3,) + tblIdx, hashedAuthPassphrase),
         (pysnmpUsmKeyEntry.name + (4,) + tblIdx, hashedPrivPassphrase))
        )

    # Commit passphrases
    pysnmpUsmSecretEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('PYSNMP-USM-MIB', 'pysnmpUsmSecretEntry')
    tblIdx = pysnmpUsmSecretEntry.getInstIdFromIndices(
        usmUserSecurityName.syntax
        )

    # Destroy&Create new row
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((pysnmpUsmSecretEntry.name + (4,) + tblIdx, 'destroy'),)
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((pysnmpUsmSecretEntry.name + (4,) + tblIdx, 'createAndGo'),
         (pysnmpUsmSecretEntry.name + (2,) + tblIdx, authKey),
         (pysnmpUsmSecretEntry.name + (3,) + tblIdx, privKey),)
        )

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
    
    # Build entry index
    snmpTargetParamsEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-TARGET-MIB', 'snmpTargetParamsEntry')
    tblIdx = snmpTargetParamsEntry.getInstIdFromIndices(name)

    # Destroy&Create new row
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
    # Build entry index
    snmpTargetAddrEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-TARGET-MIB', 'snmpTargetAddrEntry')
    tblIdx = snmpTargetAddrEntry.getInstIdFromIndices(addrName)

    if transportDomain == snmpUDPDomain:
        SnmpUDPAddress, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMPv2-TM', 'SnmpUDPAddress')
        transportAddress = SnmpUDPAddress(transportAddress)

    # Destroy&Create new row
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

def addSocketTransport(snmpEngine, transportDomain, transport):
    """Add transport object to socket dispatcher of snmpEngine"""
    if not snmpEngine.transportDispatcher:
        snmpEngine.registerTransportDispatcher(dispatch.AsynsockDispatcher())
    snmpEngine.transportDispatcher.registerTransport(
        transportDomain, transport
        )

# VACM shortcuts

def addContext(snmpEngine, contextName):
    # Create new row & fill entry
    mibInstrumController = snmpEngine.msgAndPduDsp.mibInstrumController
    vacmContextEntry, = mibInstrumController.mibBuilder.importSymbols(
        'SNMP-VIEW-BASED-ACM-MIB', 'vacmContextEntry'
        )
    tblIdx = vacmContextEntry.getInstIdFromIndices(contextName)
    mibInstrumController.writeVars(
        ((vacmContextEntry.name + (1,) + tblIdx, contextName),)
        )

def addVacmGroup(snmpEngine, groupName, securityModel, securityName):
    mibInstrumController = snmpEngine.msgAndPduDsp.mibInstrumController
    # Create new row
    vacmSecurityToGroupEntry, = mibInstrumController.mibBuilder.importSymbols(
        'SNMP-VIEW-BASED-ACM-MIB', 'vacmSecurityToGroupEntry'
        )
    tblIdx = vacmSecurityToGroupEntry.getInstIdFromIndices(
        securityModel, securityName
        )

    # Destroy&Create new row
    mibInstrumController.writeVars(
        ((vacmSecurityToGroupEntry.name + (5,) + tblIdx, 'destroy'),)
        )
    mibInstrumController.writeVars(
        ((vacmSecurityToGroupEntry.name + (5,) + tblIdx, 'createAndGo'),
        (vacmSecurityToGroupEntry.name + (1,) + tblIdx, securityModel),
        (vacmSecurityToGroupEntry.name + (2,) + tblIdx, securityName),
        (vacmSecurityToGroupEntry.name + (3,) + tblIdx, groupName),)
        )

def addVacmAccess(snmpEngine, groupName, contextName, securityModel,
                  securityLevel, prefix, readView, writeView, notifyView):
    mibInstrumController = snmpEngine.msgAndPduDsp.mibInstrumController

    addContext(snmpEngine, contextName)
    
    # Create new row
    vacmAccessEntry, = mibInstrumController.mibBuilder.importSymbols(
        'SNMP-VIEW-BASED-ACM-MIB', 'vacmAccessEntry'
        )
    tblIdx = vacmAccessEntry.getInstIdFromIndices(
        groupName, contextName, securityModel, securityLevel
        )

    # Destroy&Create new row
    mibInstrumController.writeVars(
        ((vacmAccessEntry.name + (9,) + tblIdx, 'destroy'),)
        )
    mibInstrumController.writeVars(
        ((vacmAccessEntry.name + (9,) + tblIdx, 'createAndGo'),
        (vacmAccessEntry.name + (1,) + tblIdx, contextName),
        (vacmAccessEntry.name + (2,) + tblIdx, securityModel),
        (vacmAccessEntry.name + (3,) + tblIdx, securityLevel),
        (vacmAccessEntry.name + (4,) + tblIdx, prefix),
        (vacmAccessEntry.name + (5,) + tblIdx, readView),
        (vacmAccessEntry.name + (6,) + tblIdx, writeView),
        (vacmAccessEntry.name + (7,) + tblIdx, notifyView),)
        )

def addVacmView(snmpEngine, viewName, viewType, subTree, mask):
    mibInstrumController = snmpEngine.msgAndPduDsp.mibInstrumController
    # Create new row
    vacmViewTreeFamilyEntry, = mibInstrumController.mibBuilder.importSymbols(
        'SNMP-VIEW-BASED-ACM-MIB', 'vacmViewTreeFamilyEntry'
        )
    tblIdx = vacmViewTreeFamilyEntry.getInstIdFromIndices(
        viewName, subTree
        )
    
    # Destroy&Create new row
    mibInstrumController.writeVars(
        ((vacmViewTreeFamilyEntry.name + (6,) + tblIdx, 'destroy'),)
        )
    mibInstrumController.writeVars(
        ((vacmViewTreeFamilyEntry.name + (6,) + tblIdx, 'createAndGo'),
         (vacmViewTreeFamilyEntry.name + (1,) + tblIdx, viewName),
         (vacmViewTreeFamilyEntry.name + (2,) + tblIdx, subTree),
         (vacmViewTreeFamilyEntry.name + (3,) + tblIdx, mask),
         (vacmViewTreeFamilyEntry.name + (4,) + tblIdx, viewType),)
        )

# VACM simplicity wrappers

def addRoUser(snmpEngine, securityModel, securityName, securityLevel, subTree):
    groupName = '%s-grp-%d' % (securityName, securityModel)
    SnmpSecurityLevel, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-FRAMEWORK-MIB', 'SnmpSecurityLevel')
    securityLevel = SnmpSecurityLevel(securityLevel)
    addVacmGroup(
        snmpEngine, groupName, securityModel, securityName
        )
    addVacmAccess(
        snmpEngine, groupName, '', securityModel, securityLevel, 1,
        groupName+'-view-ro', '', ''
        )
    addVacmView(
        snmpEngine, groupName+'-view-ro', 1, subTree, '',
        )

def addRwUser(snmpEngine, securityModel, securityName, securityLevel, subTree):
    groupName = '%s-grp-%d' % (securityName, securityModel)
    SnmpSecurityLevel, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-FRAMEWORK-MIB', 'SnmpSecurityLevel')
    securityLevel = SnmpSecurityLevel(securityLevel)
    addVacmGroup(
        snmpEngine, groupName, securityModel, securityName
        )
    addVacmAccess(
        snmpEngine, groupName, '', securityModel, securityLevel, 1,
        groupName+'-view-rw', groupName+'-view-rw', ''
        )
    addVacmView(
        snmpEngine, groupName+'-view-rw', 1, subTree, ''
        )

# Notification configuration

def addTrapUser(snmpEngine,securityModel,securityName,securityLevel,subTree):
    groupName = '%s-grp-%d' % (securityName, securityModel)
    SnmpSecurityLevel, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-FRAMEWORK-MIB', 'SnmpSecurityLevel')
    securityLevel = SnmpSecurityLevel(securityLevel)
    addVacmGroup(
        snmpEngine, groupName, securityModel, securityName
        )
    addVacmAccess(
        snmpEngine, groupName, '', securityModel, securityLevel, 1,
        '', '', groupName+'-view-trap',
        )
    addVacmView(
        snmpEngine, groupName+'-view-trap', 1, subTree, ''
        )

def addNotificationTarget(snmpEngine, notificationName, paramsName,
                          transportTag, notifyType=None, filterSubtree=None,
                          filterMask=None, filterType=None):
    # Configure snmpNotifyTable
    
    # Build entry index
    snmpNotifyEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-NOTIFICATION-MIB', 'snmpNotifyEntry')
    tblIdx = snmpNotifyEntry.getInstIdFromIndices(
        notificationName
        )

    # Destroy&Create new row
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyEntry.name + (5,) + tblIdx, 'destroy'),)
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyEntry.name + (5,) + tblIdx, 'createAndGo'),
         (snmpNotifyEntry.name + (2,) + tblIdx, transportTag),
         (snmpNotifyEntry.name + (3,) + tblIdx, notifyType),)
        )

    # Configure snmpNotifyFilterProfileTable
    snmpNotifyFilterProfileEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-NOTIFICATION-MIB', 'snmpNotifyFilterProfileEntry')
    tblIdx = snmpNotifyFilterProfileEntry.getInstIdFromIndices(
        paramsName
        )

    profileName = '%s-filter' % notificationName
    
    # Destroy&Create new row
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyFilterProfileEntry.name + (3,) + tblIdx, 'destroy'),)
        )
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyFilterProfileEntry.name + (3,) + tblIdx, 'createAndGo'),
         (snmpNotifyFilterProfileEntry.name + (1,) + tblIdx, profileName),)
        )

    if filterSubtree == filterMask == filterType == None:
        return

    # Configure snmpNotifyFilterEntry

    snmpNotifyFilterEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-NOTIFICATION-MIB', 'snmpNotifyFilterEntry')
    tblIdx = snmpNotifyFilterProfileEntry.getInstIdFromIndices(profileName)
    
    # Destroy&Create new row
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyFilterEntry.name + (5,) + tblIdx, 'destroy'),)
        )    
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyFilterEntry.name + (5,) + tblIdx, 'createAndGo'),
         (snmpNotifyFilterEntry.name + (1,) + tblIdx, filterSubtree),
         (snmpNotifyFilterEntry.name + (2,) + tblIdx, filterMask),
         (snmpNotifyFilterEntry.name + (3,) + tblIdx, filterType),)
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
