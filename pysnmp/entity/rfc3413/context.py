# SNMP entity context
from pyasn1.type import univ
from pyasn1.compat.octets import null
from pysnmp import error
from pysnmp import debug

class SnmpContext:
    def __init__(self, snmpEngine, contextEngineId=None):
        if contextEngineId is None:
            # Default to local snmpEngineId
            contextEngineId,= snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-FRAMEWORK-MIB', 'snmpEngineID')
            contextEngineId = contextEngineId.syntax
        self.contextEngineId = contextEngineId
        debug.logger & debug.flagIns and debug.logger('SnmpContext: contextEngineId \"%s\"' % repr(contextEngineId))
        self.contextNames = {
            null: snmpEngine.msgAndPduDsp.mibInstrumController # Default name
            } 

    def registerContextName(self, contextName, mibInstrum=None):
        contextName = univ.OctetString(contextName).asOctets()
        if contextName in self.contextNames:
            raise error.PySnmpError(
                'Duplicate contextName %s' % contextName
                )
        debug.logger & debug.flagIns and debug.logger('registerContextName: registered contextName \"%s\", mibInstrum %s' % (contextName, mibInstrum))
        if mibInstrum is None:
            self.contextNames[contextName] = self.contextNames[null]
        else:
            self.contextNames[contextName] = mibInstrum
            
    def unregisterContextName(self, contextName):
        contextName = univ.OctetString(contextName).asOctets()
        if contextName in self.contextNames:
            debug.logger & debug.flagIns and debug.logger('unregisterContextName: unregistered contextName \"%s\"' % contextName)
            del self.contextNames[contextName]

    def getMibInstrum(self, contextName):
        contextName = univ.OctetString(contextName).asOctets()
        if contextName not in self.contextNames:
            debug.logger & debug.flagIns and debug.logger('getMibInstrum: contextName \"%s\" not registered' % contextName)
            raise error.PySnmpError(
                'Missing contextName %s' % contextName
                )
        else:
            debug.logger & debug.flagIns and debug.logger('getMibInstrum: contextName \"%s\", mibInstum %s' % (contextName, self.contextNames[contextName]))
            return self.contextNames[contextName]
