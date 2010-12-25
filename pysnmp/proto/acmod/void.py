# Void Access Control Model
from pysnmp.smi.error import NoSuchObjectError
from pysnmp.proto import errind, error

accessModelID = 0

# rfc3415 3.2
def isAccessAllowed(
    snmpEngine,
    securityModel,
    securityName,
    securityLevel,
    viewType,
    contextName,
    variableName):

    debug.logger & debug.flagACL and debug.logger('isAccessAllowed: viewType %s for variableName %s - OK' % (viewType, variableName))

    # rfc3415 3.2.5c
    return error.StatusInformation(errorIndication=errind.accessAllowed)
