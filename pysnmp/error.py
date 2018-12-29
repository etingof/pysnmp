#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#

import sys


class PySnmpError(Exception):
    def __init__(self, *args):
        msg = args and str(args[0]) or ''

        self.cause = sys.exc_info()

        if self.cause[0]:
            msg += 'caused by %s: %s' % (self.cause[0], self.cause[1])

        if msg:
            args = (msg,) + args[1:]

        Exception.__init__(self, *args)
