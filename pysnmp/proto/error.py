from pysnmp import error

class ProtoError(error.PySnmpError): pass
class BadArgumentError(ProtoError): pass

# SNMP v3 exceptions

class SnmpV3Error(ProtoError): pass
class CacheExpiredError(SnmpV3Error): pass
class InternalError(SnmpV3Error): pass
class MessageProcessingError(SnmpV3Error): pass
class RequestTimeout(SnmpV3Error): pass
