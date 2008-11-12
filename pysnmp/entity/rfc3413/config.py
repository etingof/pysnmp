# Shortcuts to MIB instrumentation items used internally in SNMP applications
import string
from pysnmp.smi.error import SmiError, NoSuchObjectError
from pysnmp.smi.exval import noSuchInstance
from pysnmp.entity import config

def getVersionSpecifics(snmpVersion): pass

def getTargetAddr(snmpEngine, snmpTargetAddrName):
    mibInstrumController = snmpEngine.msgAndPduDsp.mibInstrumController
    # Transport endpoint
    snmpTargetAddrEntry, = mibInstrumController.mibBuilder.importSymbols(
        'SNMP-TARGET-MIB', 'snmpTargetAddrEntry'
        )
    tblIdx = snmpTargetAddrEntry.getInstIdFromIndices(
        snmpTargetAddrName
        )

    ((v, snmpTargetAddrTDomain),
     (v, snmpTargetAddrTAddress),
     (v, snmpTargetAddrTimeout),
     (v, snmpTargetAddrRetryCount),
     (v, snmpTargetAddrParams)) = mibInstrumController.readVars(
        ((snmpTargetAddrEntry.name + (2,) + tblIdx, None),
         (snmpTargetAddrEntry.name + (3,) + tblIdx, None),
         (snmpTargetAddrEntry.name + (4,) + tblIdx, None),
         (snmpTargetAddrEntry.name + (5,) + tblIdx, None),
         (snmpTargetAddrEntry.name + (7,) + tblIdx, None))       
        )

    if noSuchInstance.isSameTypeWith(snmpTargetAddrParams):
        raise SmiError('Target %s not configured at SMI' % snmpTargetAddrName)

    if snmpTargetAddrTDomain == config.snmpUDPDomain:
        SnmpUDPAddress, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMPv2-TM', 'SnmpUDPAddress')
        snmpTargetAddrTAddress = tuple(
            SnmpUDPAddress(snmpTargetAddrTAddress)
            )

    return ( snmpTargetAddrTDomain,
             snmpTargetAddrTAddress,
             snmpTargetAddrTimeout,
             snmpTargetAddrRetryCount,
             snmpTargetAddrParams )

def getTargetInfo(snmpEngine, snmpTargetAddrName):
    # Transport endpoint
    ( snmpTargetAddrTDomain,
      snmpTargetAddrTAddress,
      snmpTargetAddrTimeout,
      snmpTargetAddrRetryCount,
      snmpTargetAddrParams ) = getTargetAddr(snmpEngine, snmpTargetAddrName)

    mibInstrumController = snmpEngine.msgAndPduDsp.mibInstrumController

    # Target params
    snmpTargetParamsEntry, = mibInstrumController.mibBuilder.importSymbols(
        'SNMP-TARGET-MIB', 'snmpTargetParamsEntry'
        )

    tblIdx = snmpTargetParamsEntry.getInstIdFromIndices(
        snmpTargetAddrParams
        )
    ((v, snmpTargetParamsMPModel),
     (v, snmpTargetParamsSecurityModel),
     (v, snmpTargetParamsSecurityName),
     (v, snmpTargetParamsSecurityLevel)) = mibInstrumController.readVars(
        ((snmpTargetParamsEntry.name + (2,) + tblIdx, None),
         (snmpTargetParamsEntry.name + (3,) + tblIdx, None),
         (snmpTargetParamsEntry.name + (4,) + tblIdx, None),
         (snmpTargetParamsEntry.name + (5,) + tblIdx, None))
        )
    
    if noSuchInstance.isSameTypeWith(snmpTargetParamsSecurityName):
        raise SmiError('Parameters %s not configured at SMI' % snmpTargetAddrParams)

    return ( snmpTargetAddrTDomain,
             snmpTargetAddrTAddress,
             snmpTargetAddrTimeout,
             snmpTargetAddrRetryCount,
             snmpTargetParamsMPModel,
             snmpTargetParamsSecurityModel,
             snmpTargetParamsSecurityName,
             snmpTargetParamsSecurityLevel )

def getTargetParams(snmpEngine, paramsName):
    mibInstrumController = snmpEngine.msgAndPduDsp.mibInstrumController    
    snmpTargetParamsEntry, = mibInstrumController.mibBuilder.importSymbols(
        'SNMP-TARGET-MIB', 'snmpTargetParamsEntry'
        )
    tblIdx = snmpTargetParamsEntry.getInstIdFromIndices(
        paramsName
        )
    ((v, snmpTargetParamsMPModel),
     (v, snmpTargetParamsSecurityModel),
     (v, snmpTargetParamsSecurityName),
     (v, snmpTargetParamsSecurityLevel)) = mibInstrumController.readVars(
        ((snmpTargetParamsEntry.name + (2,) + tblIdx, None),
         (snmpTargetParamsEntry.name + (3,) + tblIdx, None),
         (snmpTargetParamsEntry.name + (4,) + tblIdx, None),
         (snmpTargetParamsEntry.name + (5,) + tblIdx, None))
        )

    if noSuchInstance.isSameTypeWith(snmpTargetParamsMPModel):
        raise SmiError('Parameters %s not configured at SMI' % paramsName)

    return ( snmpTargetParamsMPModel,
             snmpTargetParamsSecurityModel,
             snmpTargetParamsSecurityName,
             snmpTargetParamsSecurityLevel )

def getNotificationInfo(snmpEngine, notificationTarget):
    mibInstrumController = snmpEngine.msgAndPduDsp.mibInstrumController
    # Transport endpoint
    snmpNotifyEntry, = mibInstrumController.mibBuilder.importSymbols(
        'SNMP-NOTIFICATION-MIB', 'snmpNotifyEntry'
        )
    tblIdx = snmpNotifyEntry.getInstIdFromIndices(
        notificationTarget
        )
    ((v, snmpNotifyTag),
     (v, snmpNotifyType)) = mibInstrumController.readVars(
        ((snmpNotifyEntry.name + (2,) + tblIdx, None),
         (snmpNotifyEntry.name + (3,) + tblIdx, None))
        )

    if noSuchInstance.isSameTypeWith(snmpNotifyTag):
        raise SmiError('Target %s not configured at SMI' % notificationTarget)

    return snmpNotifyTag, snmpNotifyType

def getTargetNames(snmpEngine, tag):
    mibInstrumController = snmpEngine.msgAndPduDsp.mibInstrumController
    # Transport endpoint
    ( snmpTargetAddrEntry,
      snmpTargetAddrTagList ) = mibInstrumController.mibBuilder.importSymbols(
        'SNMP-TARGET-MIB', 'snmpTargetAddrEntry', 'snmpTargetAddrTagList'
        )
    targetNames = []
    nextName =  snmpTargetAddrTagList.name
    while 1:
        try:
            mibNode = snmpTargetAddrTagList.getNextNode(nextName)
        except NoSuchObjectError:
            break
        # XXX stop on eot
        if tag in string.split(str(mibNode.syntax), ' '): # XXX add __split__()
            idx = mibNode.name[len(snmpTargetAddrTagList.name):]
            targetNames.append(
                snmpTargetAddrEntry.getIndicesFromInstId(idx)[0]
                )
        nextName = mibNode.name
    return targetNames

# XXX
# convert cmdrsp/cmdgen into this api
