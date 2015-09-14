from pysnmp.entity.rfc3413.oneliner.ntforg import *

if version_info[:2] < (2, 6):
    def next(iter):
        return iter.next()

#
# Synchronous one-liner SNMP Notification Originator application
#

def sendNotification(snmpEngine, authData, transportTarget, contextData,
                     notifyType, varBinds, **options):

    def cbFun(snmpEngine, sendRequestHandle,
              errorIndication, errorStatus, errorIndex,
              varBinds, cbCtx):
        cbCtx['errorIndication'] = errorIndication
        cbCtx['errorStatus'] = errorStatus
        cbCtx['errorIndex'] = errorIndex
        cbCtx['varBinds'] = varBinds

    cbCtx = {}

    ntfOrg = AsyncNotificationOriginator()

    if varBinds:
        ntfOrg.sendNotification(
            snmpEngine,
            authData,
            transportTarget,
            contextData,
            notifyType,
            varBinds,
            (cbFun, cbCtx),
            options.get('lookupMib', True)
        )

        snmpEngine.transportDispatcher.runDispatcher()

        errorIndication = cbCtx.get('errorIndication')
        errorStatus = cbCtx.get('errorStatus')
        errorIndex = cbCtx.get('errorIndex')
        varBinds = cbCtx.get('varBinds', [])
    else:
        errorIndication = errorStatus = errorIndex = None
        varBinds = []

    yield errorIndication, errorStatus, errorIndex, varBinds
