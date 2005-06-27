# SNMP engine configuration functions
import string
from pysnmp.carrier.asynsock import dispatch
from pysnmp.carrier.asynsock.dgram import udp, unix
from pysnmp.proto import rfc3412
from pysnmp.proto.secmod.rfc3414 import localkey
from pysnmp.entity import engine
from pysnmp.smi.error import NotWritableError
from pysnmp import error

# XXX
snmpUDPDomain = udp.snmpUDPDomain
snmpLocalDomain = unix.snmpLocalDomain

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
    
def addV3User(snmpEngine, securityName, authKey=None, authProtocol=None,
              privKey=None, privProtocol=None, hashedAuthKey=None,
              hashedPrivKey=None):
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
    if authProtocol is None:
        usmNoAuthProtocol, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-USER-BASED-SM-MIB', 'usmNoAuthProtocol')
        usmUserAuthProtocol.syntax = usmUserAuthProtocol.syntax.clone(
            usmNoAuthProtocol.name
            )
    elif string.find('MD5', string.upper(authProtocol)) != -1:
        usmHMACMD5AuthProtocol, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-USER-BASED-SM-MIB', 'usmHMACMD5AuthProtocol')
        usmUserAuthProtocol.syntax = usmUserAuthProtocol.syntax.clone(
            usmHMACMD5AuthProtocol.name
            )
    elif string.find('SHA', string.upper(authProtocol)) != -1:
        usmHMACSHAAuthProtocol, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-USER-BASED-SM-MIB', 'usmHMACSHAAuthProtocol')
        usmUserAuthProtocol.syntax = usmUserAuthProtocol.syntax.clone(
            usmHMACSHAAuthProtocol.name
            )
    else:
        raise error.PySnmpError('Unknown auth protocol %s' % authProtocol)

    # Commit priv protocol
    usmUserPrivProtocol = usmUserEntry.getNode(
        usmUserEntry.name + (8,) + tblIdx
        )
    if privProtocol is None:
        usmNoPrivProtocol, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-USER-BASED-SM-MIB', 'usmNoPrivProtocol')
        usmUserPrivProtocol.syntax = usmUserPrivProtocol.syntax.clone(
            usmNoPrivProtocol.name
            )
    elif string.find('DES', string.upper(privProtocol)) != -1:
        usmDESPrivProtocol, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-USER-BASED-SM-MIB', 'usmDESPrivProtocol')
        usmUserPrivProtocol.syntax = usmUserPrivProtocol.syntax.clone(
            usmDESPrivProtocol.name
            )
    else:
        raise error.PySnmpError('Unknown priv protocol %s' % privProtocol)

    # Localize and commit localized keys
    if authKey is not None or hashedAuthKey is not None:
        pysnmpUsmKeyAuth = pysnmpUsmKeyEntry.getNode(
            pysnmpUsmKeyEntry.name + (3,) + tblIdx
            )
        if hashedAuthKey is not None:
            pysnmpUsmKeyAuth.syntax = pysnmpUsmKeyAuth.syntax.clone(
                hashedAuthKey
                )
        else:
            pysnmpUsmKeyAuth.syntax = pysnmpUsmKeyAuth.syntax.clone(
                localkey.hashPassphrase(authKey)
                )
        pysnmpUsmKeyAuthLocalized = pysnmpUsmKeyEntry.getNode(
            pysnmpUsmKeyEntry.name + (1,) + tblIdx
            )
        pysnmpUsmKeyAuthLocalized.syntax = pysnmpUsmKeyAuthLocalized.syntax.clone(localkey.localizeKey(pysnmpUsmKeyAuth.syntax, snmpEngineID.syntax))
    if privKey is not None or hashedPrivKey is not None:
        pysnmpUsmKeyPriv = pysnmpUsmKeyEntry.getNode(
            pysnmpUsmKeyEntry.name + (4,) + tblIdx
            )
        if hashedPrivKey is not None:
            pysnmpUsmKeyPriv.syntax = pysnmpUsmKeyPriv.syntax.clone(
                hashedPrivKey
                )
        else:
            pysnmpUsmKeyPriv.syntax = pysnmpUsmKeyPriv.syntax.clone(
                localkey.hashPassphrase(privKey)
                )
        pysnmpUsmKeyPrivLocalized = pysnmpUsmKeyEntry.getNode(
            pysnmpUsmKeyEntry.name + (2,) + tblIdx
            )
        pysnmpUsmKeyPrivLocalized.syntax = pysnmpUsmKeyPrivLocalized.syntax.clone(localkey.localizeKey(pysnmpUsmKeyPriv.syntax, snmpEngineID.syntax))

    # Commit passphrases
    pysnmpUsmSecretEntry, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('PYSNMP-USM-MIB', 'pysnmpUsmSecretEntry')
    tblIdx = pysnmpUsmSecretEntry.getInstIdFromIndices(
        usmUserSecurityName.syntax
        )
    # Create new row
    snmpEngine.msgAndPduDsp.mibInstrumController.writeVars(
        ((pysnmpUsmSecretEntry.name + (4,) + tblIdx, 4),)
        )
    if authKey is not None:
        pysnmpUsmSecretAuthKey = pysnmpUsmSecretEntry.getNode(
            pysnmpUsmSecretEntry.name + (2,) + tblIdx
            )
        pysnmpUsmSecretAuthKey.syntax = pysnmpUsmSecretAuthKey.syntax.clone(
            authKey
            )
    if privKey is not None:
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
    else:
        securityModel = 3
    
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
