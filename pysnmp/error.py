#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#

import sys


class PySnmpError(Exception):
    def __init__(self, message):
        self.cause = sys.exc_info()
        Exception.__init__(self, '%s, caused by %s: %s' % (message, self.cause[0], self.cause[1]))
