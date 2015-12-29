#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2016, Ilya Etingof <ilya@glas.net>
# License: http://pysnmp.sf.net/license.html
#
from pysnmp.proto import errind, error
from pysnmp import debug

# rfc3415 3.2
class Vacm:
    """Void Access Control Model"""
    accessModelID = 0
    def isAccessAllowed(self,
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
