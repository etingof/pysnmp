from pysnmp.error import PySnmpError

__all__ = [
    'SmiError', 'NotInitializedError', 'NoSuchInstanceError',
    'InconsistentValueError', 'WrongValueError',
    'NoAccessError', 'ReadOnlyError', 'NotWritableError',
    'NoCreationError', 'RowCreationWanted', 'RowDestructionWanted'
    ]

class SmiError(PySnmpError): pass
class NotInitializedError(SmiError): pass
class NoSuchModuleError(SmiError): pass
class MibVariableError(SmiError): pass
class NoSuchInstanceError(MibVariableError): pass
class InconsistentValueError(MibVariableError): pass
class WrongValueError(MibVariableError): pass
class NoAccessError(MibVariableError): pass
class ReadOnlyError(MibVariableError): pass
class NotWritableError(MibVariableError): pass
class NoCreationError(MibVariableError): pass
# Row management
class RowCreationWanted(MibVariableError): pass
class RowDestructionWanted(MibVariableError): pass
