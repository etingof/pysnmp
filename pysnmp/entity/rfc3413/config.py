# Shortcuts to MIB instrumentation items used internally in SNMP applications
import string

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
    snmpTargetAddrTDomain = snmpTargetAddrEntry.getNode(
        snmpTargetAddrEntry.name + (2,) + tblIdx
        )
    snmpTargetAddrTAddress = snmpTargetAddrEntry.getNode(
        snmpTargetAddrEntry.name + (3,) + tblIdx
        )
    snmpTargetAddrTimeout = snmpTargetAddrEntry.getNode(
        snmpTargetAddrEntry.name + (4,) + tblIdx
        )
    snmpTargetAddrRetryCount = snmpTargetAddrEntry.getNode(
        snmpTargetAddrEntry.name + (5,) + tblIdx
        )
    snmpTargetAddrParams = snmpTargetAddrEntry.getNode(
        snmpTargetAddrEntry.name + (7,) + tblIdx
        )

    return ( snmpTargetAddrTDomain.syntax,
             snmpTargetAddrTAddress.syntax,
             snmpTargetAddrTimeout.syntax,
             snmpTargetAddrRetryCount.syntax,
             snmpTargetAddrParams.syntax )

def getTargetParams(snmpEngine, paramsName):
    snmpTargetParamsEntry, = mibInstrumController.mibBuilder.importSymbols(
        'SNMP-TARGET-MIB', 'snmpTargetParamsEntry'
        )
    tblIdx = snmpTargetParamsEntry.getInstIdFromIndices(
        paramsName
        )
    snmpTargetParamsMPModel = snmpTargetParamsEntry.getNode(
        snmpTargetParamsEntry.name + (2,) + tblIdx
        )
    snmpTargetParamsSecurityModel = snmpTargetParamsEntry.getNode(
        snmpTargetParamsEntry.name + (3,) + tblIdx
        )
    snmpTargetParamsSecurityName = snmpTargetParamsEntry.getNode(
        snmpTargetParamsEntry.name + (4,) + tblIdx
        )
    snmpTargetParamsSecurityLevel = snmpTargetParamsEntry.getNode(
        snmpTargetParamsEntry.name + (5,) + tblIdx
        )

    return ( snmpTargetAddrTDomain.syntax,
             snmpTargetAddrTAddress.syntax.getNativeValue(),
             snmpTargetAddrTimeout.syntax,
             snmpTargetAddrRetryCount.syntax,
             snmpTargetParamsMPModel.syntax,
             snmpTargetParamsSecurityModel.syntax,
             snmpTargetParamsSecurityName.syntax,
             snmpTargetParamsSecurityLevel.syntax )

def getNotificationInfo(snmpEngine, notificationTarget):
    mibInstrumController = snmpEngine.msgAndPduDsp.mibInstrumController
    # Transport endpoint
    snmpNotifyEntry, = mibInstrumController.mibBuilder.importSymbols(
        'SNMP-NOTIFICATION-MIB', 'snmpNotifyEntry'
        )
    tblIdx = snmpNotifyEntry.getInstIdFromIndices(
        notificationTarget
        )
    snmpNotifyTag = snmpNotifyEntry.getNode(
        snmpNotifyEntry.name + (2,) + tblIdx
        )
    snmpNotifyType = snmpNotifyEntry.getNode(
        snmpNotifyEntry.name + (3,) + tblIdx
        )
    return snmpNotifyTag, snmpNotifyType

def getTargetNames(snmpEngine, tag):
    mibInstrumController = snmpEngine.msgAndPduDsp.mibInstrumController
    # Transport endpoint
    snmpTargetAddrEntry, = mibInstrumController.mibBuilder.importSymbols(
        'SNMP-TARGET-MIB', 'snmpTargetAddrEntry'
        )
    targetNames = []
    nextName =  snmpTargetAddrEntry.name + (6,)
    while 1:
        try:
            mibNode = snmpTargetAddrEntry.getNextNode(nextName)
        except NoSuchInstanceError:
            break
        # XXX stop on eot
        if tag in string.split(str(mibNode.syntax)): # XXX add __split__()
            targetNames.append(
                snmpTargetAddrEntry.getIndicesFromInstId(mibNode.name)[0]
                )
        nextName = mibNode.name
    return targetNames

# XXX
# convert cmdrsp/cmdgen into this api
