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

from pysnmp import hlapi
from pysnmp import debug
from pysnmp import error


class ContextDataTestCase(BaseTestCase):
    def testDefaults(self):
        context = hlapi.ContextData()
        self.assertFalse(context.contextEngineId)
        self.assertFalse(context.contextName)

    def testContextEngineId(self):
        context = hlapi.ContextData(hlapi.OctetString('abc'))
        self.assertEqual(context.contextEngineId, hlapi.OctetString('abc'))
        self.assertFalse(context.contextName)

    def testContextName(self):
        context = hlapi.ContextData(contextName=hlapi.OctetString('abc'))
        self.assertFalse(context.contextEngineId)
        self.assertEqual(context.contextName, hlapi.OctetString('abc'))


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
