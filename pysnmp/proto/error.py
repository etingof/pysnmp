from pyasn1.error import PyAsn1Error
from pysnmp.error import PySnmpError

class ProtocolError(PySnmpError, PyAsn1Error): pass

# SNMP v3 exceptions

class SnmpV3Error(ProtocolError): pass
class StatusInformation(SnmpV3Error):
    def __init__(self, **kwargs):
#        print kwargs
        self.__errorIndication = kwargs
    def __str__(self): return str(self.__errorIndication)
    def __getitem__(self, key): return self.__errorIndication[key]
    def has_key(self, key): return self.__errorIndication.has_key(key)
    def get(self, key, defVal=None):
        return self.__errorIndication.get(key, defVal)
class CacheExpiredError(SnmpV3Error): pass
class InternalError(SnmpV3Error): pass
class MessageProcessingError(SnmpV3Error): pass
class RequestTimeout(SnmpV3Error): pass
