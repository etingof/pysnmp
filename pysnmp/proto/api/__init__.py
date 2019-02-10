#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pysnmp.proto.api import v1, v2c, verdec

# Protocol versions
SNMP_VERSION_1 = 0
SNMP_VERSION_2C = 1
PROTOCOL_MODULES = {SNMP_VERSION_1: v1, SNMP_VERSION_2C: v2c}

decodeMessageVersion = verdec.decodeMessageVersion
