# SNMP entity context
from pysnmp import error

class SnmpContext:
    def __init__(self, snmpEngine, contextEngineId=None):
        if contextEngineId is None:
            # Default to local snmpEngineId
            contextEngineId,= snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('SNMP-FRAMEWORK-MIB', 'snmpEngineID')
            contextEngineId = contextEngineId.syntax
        self.contextEngineId = contextEngineId
        self.contextNames = {
            '': snmpEngine.msgAndPduDsp.mibInstrumController # Default name
            } 

    def registerContextName(self, contextName, mibInstrum=None):
        if self.contextNames.has_key(contextName):
            raise error.PySnmpError(
                'Duplicate contextName %s' % contextName
                )
        if mibInstrum is None:
            self.contextName[contextName] = self.contextName['']
        else:
            self.contextName[contextName] = mibInstrum
            
    def unregisterContextName(self, contextName):
        if self.contextNames.has_key(contextName):
            del self.contextName[contextName]

    def getMibInstrum(self, contextName):
        if not self.contextNames.has_key(contextName):
            raise error.PySnmpError(
                'Missing contextName %s' % contextName
                )
        else:
            return self.contextNames[contextName]
