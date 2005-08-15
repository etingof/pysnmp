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
                contextEngineID=None, contextName=None,
                transportTag=None):
    snmpEngineID, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-FRAMEWORK-MIB', 'snmpEngineID')

    # Build entry index
    snmpCommunityEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-COMMUNITY-MIB', 'snmpCommunityEntry')
    tblIdx = snmpCommunityEntry.getInstIdFromIndices(
        snmpEngineID.syntax, securityName
        )

    # Create new row
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpCommunityEntry.name + (8,) + tblIdx, 4),) # XXX symbolic names
        )

    # Commit table cell
    snmpCommunityName = snmpCommunityEntry.getNode(
        snmpCommunityEntry.name + (2,) + tblIdx
        )
    snmpCommunityName.syntax = snmpCommunityName.syntax.clone(communityName)
    
    snmpCommunitySecurityName = snmpCommunityEntry.getNode(
        snmpCommunityEntry.name + (3,) + tblIdx
        )
    snmpCommunitySecurityName.syntax = snmpCommunitySecurityName.syntax.clone(
        securityName
        )

    if contextEngineID is None:
        contextEngineID = snmpEngineID.syntax

    snmpCommunityContextEngineID = snmpCommunityEntry.getNode(
        snmpCommunityEntry.name + (4,) + tblIdx
        )
    snmpCommunityContextEngineID.syntax = snmpCommunityContextEngineID.syntax.clone(contextEngineID)

    if contextName is not None:
        snmpCommunityContextName = snmpCommunityEntry.getNode(
            snmpCommunityEntry.name + (5,) + tblIdx
            )
        snmpCommunityContextName.syntax = snmpCommunityContextName.syntax.clone(communityName)

    if transportTag is not None:
        snmpCommunityTransportTag = snmpCommunityEntry.getNode(
            snmpCommunityEntry.name + (6,) + tblIdx
            )
        snmpCommunityTransportTag.syntax = snmpCommunityTransportTag.syntax.clone(snmpCommunityTransportTag)
    
def addV3User(snmpEngine, securityName,
              authProtocol=usmNoAuthProtocol, authKey='',
              privProtocol=usmNoPrivProtocol, privKey=''):
    # v3 setup
    snmpEngineID, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-FRAMEWORK-MIB', 'snmpEngineID')

    # Build entry index
    usmUserEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-USER-BASED-SM-MIB', 'usmUserEntry')
    tblIdx = usmUserEntry.getInstIdFromIndices(
        snmpEngineID.syntax, securityName
        )

    # Load augmenting table before creating new row in base one
    pysnmpUsmKeyEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('PYSNMP-USM-MIB', 'pysnmpUsmKeyEntry')

    # Create new row
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((usmUserEntry.name + (13,) + tblIdx, 4),)
        )
    
    # Commit username (may not be needed)    
    usmUserSecurityName = usmUserEntry.getNode(
        usmUserEntry.name + (3,) + tblIdx
        )
    usmUserSecurityName.syntax = usmUserSecurityName.syntax.clone(securityName)

    # Commit clone-from (may not be needed)
    zeroDotZero, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMPv2-SMI', 'zeroDotZero')
    usmUserCloneFrom = usmUserEntry.getNode(
        usmUserEntry.name + (4,) + tblIdx
        )
    usmUserCloneFrom.syntax = usmUserCloneFrom.syntax.clone(zeroDotZero.name)

    # Commit auth protocol
    usmUserAuthProtocol = usmUserEntry.getNode(
        usmUserEntry.name + (5,) + tblIdx
        )
    usmUserAuthProtocol.syntax = usmUserAuthProtocol.syntax.clone(authProtocol)
    if authProtocol == usmHMACMD5AuthProtocol:
        hashedAuthPassphrase = localkey.hashPassphraseMD5(authKey)
        localAuthKey = localkey.localizeKeyMD5(
            hashedAuthPassphrase, snmpEngineID.syntax
            )
    elif authProtocol == usmHMACSHAAuthProtocol:
        hashedAuthPassphrase = localkey.hashPassphraseSHA(authKey)
        localAuthKey = localkey.localizeKeySHA(
            hashedAuthPassphrase, snmpEngineID.syntax
            )
    elif authProtocol == usmNoAuthProtocol:
        pass
    else:
        raise error.PySnmpError('Unknown auth protocol %s' % (authProtocol,))

    # Commit priv protocol
    usmUserPrivProtocol = usmUserEntry.getNode(
        usmUserEntry.name + (8,) + tblIdx
        )
    usmUserPrivProtocol.syntax = usmUserPrivProtocol.syntax.clone(privProtocol)
    if privProtocol == usmDESPrivProtocol:
        if authProtocol == usmHMACMD5AuthProtocol:
            hashedPrivPassphrase = localkey.hashPassphraseMD5(privKey)
            localPrivKey = localkey.localizeKeyMD5(
                hashedPrivPassphrase, snmpEngineID.syntax
                )
        elif authProtocol == usmHMACSHAAuthProtocol:
            hashedPrivPassphrase = localkey.hashPassphraseSHA(privKey)
            localPrivKey = localkey.localizeKeySHA(
                hashedPrivPassphrase, snmpEngineID.syntax
                )
        else:
            raise error.PySnmpError(
                'Unknown auth protocol %s' % (authProtocol,)
                )
    elif privProtocol == usmNoPrivProtocol:
        pass
    else:
        raise error.PySnmpError(
            'Unknown priv protocol %s' % (privProtocol,)
            )

    # Localize and commit localized keys
    if authProtocol != usmNoAuthProtocol:
        pysnmpUsmKeyAuth = pysnmpUsmKeyEntry.getNode(
            pysnmpUsmKeyEntry.name + (3,) + tblIdx
            )
        pysnmpUsmKeyAuth.syntax = pysnmpUsmKeyAuth.syntax.clone(
            hashedAuthPassphrase
            )
        pysnmpUsmKeyAuthLocalized = pysnmpUsmKeyEntry.getNode(
            pysnmpUsmKeyEntry.name + (1,) + tblIdx
            )
        pysnmpUsmKeyAuthLocalized.syntax = pysnmpUsmKeyAuthLocalized.syntax.clone(localAuthKey)
    if privProtocol != usmNoPrivProtocol:
        pysnmpUsmKeyPriv = pysnmpUsmKeyEntry.getNode(
            pysnmpUsmKeyEntry.name + (4,) + tblIdx
            )
        pysnmpUsmKeyPriv.syntax = pysnmpUsmKeyPriv.syntax.clone(
            hashedPrivPassphrase
            )
        pysnmpUsmKeyPrivLocalized = pysnmpUsmKeyEntry.getNode(
            pysnmpUsmKeyEntry.name + (2,) + tblIdx
            )
        pysnmpUsmKeyPrivLocalized.syntax = pysnmpUsmKeyPrivLocalized.syntax.clone(localPrivKey)
    # Commit passphrases
    pysnmpUsmSecretEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('PYSNMP-USM-MIB', 'pysnmpUsmSecretEntry')
    tblIdx = pysnmpUsmSecretEntry.getInstIdFromIndices(
        usmUserSecurityName.syntax
        )
    # Create new row
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((pysnmpUsmSecretEntry.name + (4,) + tblIdx, 4),)
        )
    if authProtocol != usmNoAuthProtocol:
        pysnmpUsmSecretAuthKey = pysnmpUsmSecretEntry.getNode(
            pysnmpUsmSecretEntry.name + (2,) + tblIdx
            )
        pysnmpUsmSecretAuthKey.syntax = pysnmpUsmSecretAuthKey.syntax.clone(
            authKey
            )
    if privProtocol != usmDESPrivProtocol:
        pysnmpUsmSecretPrivKey = pysnmpUsmSecretEntry.getNode(
            pysnmpUsmSecretEntry.name + (3,) + tblIdx
            )
        pysnmpUsmSecretPrivKey.syntax = pysnmpUsmSecretPrivKey.syntax.clone(
            privKey
            )

def addTargetParams(
    snmpEngine,
    name,
    securityName,
    securityLevel,
    mpModel=3  # 0 == SNMPv1, 1 == SNMPv2c, 3 == SNMPv3
    ):
    # Build entry index
    snmpTargetParamsEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-TARGET-MIB', 'snmpTargetParamsEntry')
    tblIdx = snmpTargetParamsEntry.getInstIdFromIndices(name)

    # Create new row
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpTargetParamsEntry.name + (7,) + tblIdx, 4),)
        )

    if mpModel == 0:
        securityModel = 1
    elif mpModel == 1 or mpModel == 2:
        securityModel = 2
    elif mpModel == 3:
        securityModel = 3
    else:
        raise error.PySnmpError('Unknown MP model %s' % mpModel)
    
    # Fill entries
    snmpTargetParamsName = snmpTargetParamsEntry.getNode(
        snmpTargetParamsEntry.name + (1,) + tblIdx
        )
    snmpTargetParamsName.syntax = snmpTargetParamsName.syntax.clone(
        name
        )
    snmpTargetParamsMPModel = snmpTargetParamsEntry.getNode(
        snmpTargetParamsEntry.name + (2,) + tblIdx
        )
    snmpTargetParamsMPModel.syntax = snmpTargetParamsMPModel.syntax.clone(
        mpModel
        )
    snmpTargetParamsSecurityModel = snmpTargetParamsEntry.getNode(
        snmpTargetParamsEntry.name + (3,) + tblIdx
        )
    snmpTargetParamsSecurityModel.syntax = snmpTargetParamsSecurityModel.syntax.clone(
        securityModel
        )
    snmpTargetParamsSecurityName = snmpTargetParamsEntry.getNode(
        snmpTargetParamsEntry.name + (4,) + tblIdx
        )
    snmpTargetParamsSecurityName.syntax = snmpTargetParamsSecurityName.syntax.clone(
        securityName
        )
    snmpTargetParamsSecurityLevel = snmpTargetParamsEntry.getNode(
        snmpTargetParamsEntry.name + (5,) + tblIdx
        )
    snmpTargetParamsSecurityLevel.syntax = snmpTargetParamsSecurityLevel.syntax.clone(
        securityLevel
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

    # Create new row
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpTargetAddrEntry.name + (9,) + tblIdx, 4),)
        )
    
    # Fill entries
    snmpTargetAddrName = snmpTargetAddrEntry.getNode(
        snmpTargetAddrEntry.name + (1,) + tblIdx
        )
    snmpTargetAddrName.syntax = snmpTargetAddrName.syntax.clone(
        addrName
        )
    snmpTargetAddrTDomain = snmpTargetAddrEntry.getNode(
        snmpTargetAddrEntry.name + (2,) + tblIdx
        )
    snmpTargetAddrTDomain.syntax = snmpTargetAddrTDomain.syntax.clone(
        transportDomain
        )
    snmpTargetAddrTAddress = snmpTargetAddrEntry.getNode(
        snmpTargetAddrEntry.name + (3,) + tblIdx
        )
    if transportDomain == snmpUDPDomain:
        SnmpUDPAddress, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMPv2-TM', 'SnmpUDPAddress')
        snmpTargetAddrTAddress.syntax = SnmpUDPAddress(transportAddress)
    else: # XXX is this correct?
        snmpTargetAddrTAddress.syntax = snmpTargetAddrTAddress.syntax.clone(
            transportAddress
            )
    if timeout is not None:
        snmpTargetAddrTimeout = snmpTargetAddrEntry.getNode(
            snmpTargetAddrEntry.name + (4,) + tblIdx
            )
        snmpTargetAddrTimeout.syntax = snmpTargetAddrTimeout.syntax.clone(
            timeout
            )
    if retryCount is not None:
        snmpTargetAddrRetryCount = snmpTargetAddrEntry.getNode(
            snmpTargetAddrEntry.name + (5,) + tblIdx
            )
        snmpTargetAddrRetryCount.syntax = snmpTargetAddrRetryCount.syntax.clone(
            retryCount
            )
    snmpTargetAddrTagList = snmpTargetAddrEntry.getNode(
        snmpTargetAddrEntry.name + (6,) + tblIdx
        )
    snmpTargetAddrTagList.syntax = snmpTargetAddrTagList.syntax.clone(
        '%s %s' % (addrName, tagList) # XXX
        )
    snmpTargetAddrParams = snmpTargetAddrEntry.getNode(
        snmpTargetAddrEntry.name + (7,) + tblIdx
        )
    snmpTargetAddrParams.syntax = snmpTargetAddrParams.syntax.clone(
        params
        )

def addSocketTransport(snmpEngine, transportDomain, transport):
    """Add transport object to socket dispatcher of snmpEngine"""
    if snmpEngine.transportDispatcher is not None:
        snmpEngine.unregisterTransportDispatcher()
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
    try:
        mibInstrumController.writeVars(
            ((vacmContextEntry.name + (1,) + tblIdx, None),)
            )
    except NotWritableError: # XXX kludgy
        pass        
    vacmContextName = vacmContextEntry.getNode(
        vacmContextEntry.name + (1,) + tblIdx
        )
    vacmContextName.syntax = vacmContextName.syntax.clone(contextName)

def addVacmGroup(snmpEngine, groupName, securityModel, securityName):
    mibInstrumController = snmpEngine.msgAndPduDsp.mibInstrumController
    # Create new row
    vacmSecurityToGroupEntry, = mibInstrumController.mibBuilder.importSymbols(
        'SNMP-VIEW-BASED-ACM-MIB', 'vacmSecurityToGroupEntry'
        )
    tblIdx = vacmSecurityToGroupEntry.getInstIdFromIndices(
        securityModel, securityName
        )
    mibInstrumController.writeVars(
        ((vacmSecurityToGroupEntry.name + (5,) + tblIdx, 4),)
        )

    # Fill entries
    vacmSecurityModel = vacmSecurityToGroupEntry.getNode(
        vacmSecurityToGroupEntry.name + (1,) + tblIdx
        )
    vacmSecurityModel.syntax = vacmSecurityModel.syntax.clone(securityModel)

    vacmSecurityName = vacmSecurityToGroupEntry.getNode(
        vacmSecurityToGroupEntry.name + (2,) + tblIdx
        )
    vacmSecurityName.syntax = vacmSecurityName.syntax.clone(securityName)
    
    vacmGroupName = vacmSecurityToGroupEntry.getNode(
        vacmSecurityToGroupEntry.name + (3,) + tblIdx
        )
    vacmGroupName.syntax = vacmGroupName.syntax.clone(groupName)

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
    mibInstrumController.writeVars(
        ((vacmAccessEntry.name + (9,) + tblIdx, 4),)
        )

    # Fill entries
    vacmAccessContextPrefix = vacmAccessEntry.getNode(
        vacmAccessEntry.name + (1,) + tblIdx
        )
    vacmAccessContextPrefix.syntax = vacmAccessContextPrefix.syntax.clone(
        prefix
        )
    
    vacmAccessSecurityModel = vacmAccessEntry.getNode(
        vacmAccessEntry.name + (2,) + tblIdx
        )
    vacmAccessSecurityModel.syntax = vacmAccessSecurityModel.syntax.clone(
        securityModel
        )

    vacmAccessSecurityLevel = vacmAccessEntry.getNode(
        vacmAccessEntry.name + (3,) + tblIdx
        )
    vacmAccessSecurityLevel.syntax = vacmAccessSecurityLevel.syntax.clone(
        securityLevel
        )

    if readView:
        vacmAccessReadViewName = vacmAccessEntry.getNode(
            vacmAccessEntry.name + (5,) + tblIdx
            )
        vacmAccessReadViewName.syntax = vacmAccessReadViewName.syntax.clone(
            readView
            )

    if writeView:
        vacmAccessWriteViewName = vacmAccessEntry.getNode(
            vacmAccessEntry.name + (6,) + tblIdx
            )
        vacmAccessWriteViewName.syntax = vacmAccessWriteViewName.syntax.clone(
            writeView
            )

    if notifyView:
        vacmAccessNotifyViewName = vacmAccessEntry.getNode(
            vacmAccessEntry.name + (7,) + tblIdx
            )
        vacmAccessNotifyViewName.syntax = vacmAccessNotifyViewName.syntax.clone(
            notifyView
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
    mibInstrumController.writeVars(
        ((vacmViewTreeFamilyEntry.name + (6,) + tblIdx, 4),)
        )

    # Fill entries
    vacmViewTreeFamilyViewName = vacmViewTreeFamilyEntry.getNode(
        vacmViewTreeFamilyEntry.name + (1,) + tblIdx
        )
    vacmViewTreeFamilyViewName.syntax=vacmViewTreeFamilyViewName.syntax.clone(
        viewName
        )

    vacmViewTreeFamilySubtree = vacmViewTreeFamilyEntry.getNode(
        vacmViewTreeFamilyEntry.name + (2,) + tblIdx
        )
    vacmViewTreeFamilySubtree.syntax=vacmViewTreeFamilySubtree.syntax.clone(
        subTree
        )

    vacmViewTreeFamilyMask = vacmViewTreeFamilyEntry.getNode(
        vacmViewTreeFamilyEntry.name + (3,) + tblIdx
        )
    vacmViewTreeFamilyMask.syntax = vacmViewTreeFamilyMask.syntax.clone(
        mask
        )

    vacmViewTreeFamilyType = vacmViewTreeFamilyEntry.getNode(
        vacmViewTreeFamilyEntry.name + (4,) + tblIdx
        )
    vacmViewTreeFamilyType.syntax = vacmViewTreeFamilyType.syntax.clone(
        viewType
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

def addNotificationTarget(snmpEngine, notificationName, paramsName,
                          transportTag, notifyType=None, filterSubtree=None,
                          filterMask=None, filterType=None):
    # Configure snmpNotifyTable
    
    # Build entry index
    snmpNotifyEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-NOTIFICATION-MIB', 'snmpNotifyEntry')
    tblIdx = snmpNotifyEntry.getInstIdFromIndices(
        notificationName
        )

    # Create new row
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyEntry.name + (5,) + tblIdx, 4),)
        )

    # Commit table cell
    snmpNotifyTag = snmpNotifyEntry.getNode(
        snmpNotifyEntry.name + (2,) + tblIdx
        )
    snmpNotifyTag.syntax = snmpNotifyTag.syntax.clone(transportTag)

    if notifyType is not None:
        snmpNotifyType = snmpNotifyEntry.getNode(
            snmpNotifyEntry.name + (3,) + tblIdx
            )
        snmpNotifyType.syntax = snmpNotifyType.syntax.clone(notifyType)

    # Configure snmpNotifyFilterProfileTable
    snmpNotifyFilterProfileEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-NOTIFICATION-MIB', 'snmpNotifyFilterProfileEntry')
    tblIdx = snmpNotifyFilterProfileEntry.getInstIdFromIndices(
        paramsName
        )

    # Create new row
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyFilterProfileEntry.name + (3,) + tblIdx, 4),)
        )

    profileName = '%s-filter' % notificationName
    
    # Commit table cell
    snmpNotifyFilterProfileName = snmpNotifyFilterProfileEntry.getNode(
        snmpNotifyFilterProfileEntry.name + (1,) + tblIdx
        )
    snmpNotifyFilterProfileName.syntax = snmpNotifyFilterProfileName.syntax.clone(profileName)
    
    # Configure snmpNotifyFilterEntry

    snmpNotifyFilterEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-NOTIFICATION-MIB', 'snmpNotifyFilterEntry')
    tblIdx = snmpNotifyFilterProfileEntry.getInstIdFromIndices(profileName)

    if filterSubtree == filterMask == filterType == None:
        return
    
    # Create new row
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((snmpNotifyFilterEntry.name + (5,) + tblIdx, 4),)
        )
    
    # Commit table cell
    snmpNotifyFilterSubtree =snmpNotifyFilterEntry.getNode(
        snmpNotifyFilterEntry.name + (1,) + tblIdx
        )
    snmpNotifyFilterSubtree.syntax = snmpNotifyFilterSubtree.syntax.clone(
        filterSubtree
        )

    snmpNotifyFilterMask =snmpNotifyFilterEntry.getNode(
        snmpNotifyFilterEntry.name + (2,) + tblIdx
        )
    snmpNotifyFilterMask.syntax = snmpNotifyFilterMask.syntax.clone(
        filterMask
        )

    snmpNotifyFilterType =snmpNotifyFilterEntry.getNode(
        snmpNotifyFilterEntry.name + (3,) + tblIdx
        )
    snmpNotifyFilterType.syntax = snmpNotifyFilterType.syntax.clone(
        filterType
        )
