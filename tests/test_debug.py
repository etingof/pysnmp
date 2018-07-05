#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
import sys

try:
    import unittest2 as unittest

except ImportError:
    import unittest

from tests.base import BaseTestCase

from pysnmp import debug
from pysnmp import error


class DebugTestCase(BaseTestCase):
    def testKnownFlags(self):
        debug.setLogger(0)
        debug.setLogger(debug.Debug('all', 'io', 'dsp', 'msgproc', 'secmod',
                                    'mibbuild', 'mibinstrum', 'acl', 'proxy', 'app',
                                    printer=lambda *v, **kw: v))
        debug.setLogger(0)

    def testUnknownFlags(self):
        try:
            debug.setLogger(debug.Debug('all', 'unknown', loggerName='xxx'))

        except error.PySnmpError:
            debug.setLogger(0)
            return

        else:
            debug.setLogger(0)
            assert 0, 'unknown debug flag tolerated'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
