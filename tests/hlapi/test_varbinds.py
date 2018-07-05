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
from pysnmp.hlapi import varbinds
from pysnmp import debug
from pysnmp import error


class CommandGeneratorVarBindsTestCase(BaseTestCase):
    def testResolveFromObjectType(self):
        cg = varbinds.CommandGeneratorVarBinds()
        vb = cg.makeVarBinds(
            hlapi.SnmpEngine(),
            [hlapi.ObjectType(hlapi.ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
             hlapi.ObjectType(hlapi.ObjectIdentity('SNMPv2-MIB', 'sysUpTime', 0))]
        )
        self.assertEqual(tuple(vb[0][0]), (1, 3, 6, 1, 2, 1, 1, 1, 0))
        self.assertEqual(tuple(vb[1][0]), (1, 3, 6, 1, 2, 1, 1, 3, 0))
        self.assertFalse(vb[0][1])
        self.assertFalse(vb[1][1])

    def testResolveFromObjectIdentity(self):
        cg = varbinds.CommandGeneratorVarBinds()
        vb = cg.makeVarBinds(
            hlapi.SnmpEngine(),
            [(hlapi.ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0), 'abc'),
             (hlapi.ObjectIdentity('SNMPv2-MIB', 'sysUpTime', 0), 123)]
        )
        self.assertEqual(tuple(vb[0][0]), (1, 3, 6, 1, 2, 1, 1, 1, 0))
        self.assertEqual(tuple(vb[1][0]), (1, 3, 6, 1, 2, 1, 1, 3, 0))
        self.assertEqual(str(vb[0]), 'SNMPv2-MIB::sysDescr.0 = abc')
        self.assertEqual(str(vb[1]), 'SNMPv2-MIB::sysUpTime.0 = 123')
        self.assertEqual(vb[0][1], hlapi.OctetString('abc'))
        self.assertEqual(vb[1][1], 123)

    def testUnresolveWithMibLookup(self):
        cg = varbinds.CommandGeneratorVarBinds()
        vb = cg.unmakeVarBinds(
            hlapi.SnmpEngine(),
            [(hlapi.ObjectIdentifier((1, 3, 6, 1, 2, 1, 1, 1, 0)), hlapi.OctetString('abc')),
             (hlapi.ObjectIdentifier((1, 3, 6, 1, 2, 1, 1, 3, 0)), hlapi.Integer(123))]
        )
        self.assertEqual(str(vb[0]), 'SNMPv2-MIB::sysDescr.0 = abc')
        self.assertEqual(str(vb[1]), 'SNMPv2-MIB::sysUpTime.0 = 123')
        self.assertEqual(vb[0][1], hlapi.OctetString('abc'))
        self.assertEqual(vb[1][1], 123)

    def testUnresolveWithoutMibLookup(self):
        cg = varbinds.CommandGeneratorVarBinds()
        vb = cg.unmakeVarBinds(
            hlapi.SnmpEngine(),
            [(hlapi.ObjectIdentifier((1, 3, 6, 1, 2, 1, 1, 1, 0)), hlapi.OctetString('abc')),
             (hlapi.ObjectIdentifier((1, 3, 6, 1, 2, 1, 1, 3, 0)), hlapi.Integer(123))],
            lookupMib=False
        )
        self.assertEqual(str(vb[0][0]), '1.3.6.1.2.1.1.1.0')
        self.assertEqual(str(vb[1][0]), '1.3.6.1.2.1.1.3.0')
        self.assertEqual(vb[0][1], hlapi.OctetString('abc'))
        self.assertEqual(vb[1][1], 123)


class NotificationOriginatorVarBindsTestCase(BaseTestCase):
    def testResolveFromNotificationType(self):
        cg = varbinds.NotificationOriginatorVarBinds()
        vb = cg.makeVarBinds(
            hlapi.SnmpEngine(),
            hlapi.NotificationType(hlapi.ObjectIdentity('SNMPv2-MIB', 'coldStart'))
        )
        self.assertEqual(tuple(vb[0][0]), (1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0))
        self.assertEqual(tuple(vb[0][1]), (1, 3, 6, 1, 6, 3, 1, 1, 5, 1))

    def testResolveFromObjectType(self):
        cg = varbinds.NotificationOriginatorVarBinds()
        vb = cg.makeVarBinds(
            hlapi.SnmpEngine(),
            [hlapi.ObjectType(hlapi.ObjectIdentity('SNMPv2-MIB', 'snmpTrapOID', 0),
                              '1.3.6.1.6.3.1.1.5.1')]
        )
        self.assertEqual(tuple(vb[0][0]), (1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0))
        self.assertEqual(tuple(vb[0][1]), (1, 3, 6, 1, 6, 3, 1, 1, 5, 1))

    def testResolveFromObjectIdentity(self):
        cg = varbinds.NotificationOriginatorVarBinds()
        vb = cg.makeVarBinds(
            hlapi.SnmpEngine(),
            [(hlapi.ObjectIdentity('SNMPv2-MIB', 'snmpTrapOID', 0), '1.3.6.1.6.3.1.1.5.1')]
        )
        self.assertEqual(tuple(vb[0][0]), (1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0))
        self.assertEqual(tuple(vb[0][1]), (1, 3, 6, 1, 6, 3, 1, 1, 5, 1))

    def testUnresolveWithMibLookup(self):
        cg = varbinds.NotificationOriginatorVarBinds()
        vb = cg.unmakeVarBinds(
            hlapi.SnmpEngine(),
            [(hlapi.ObjectIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)),
              hlapi.ObjectIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 5, 1)))]
        )
        # TODO(etingof): why not resolve into NotificationType?
        self.assertEqual(str(vb[0][0]), '1.3.6.1.6.3.1.1.4.1.0')
        self.assertEqual(str(vb[0][1]), '1.3.6.1.6.3.1.1.5.1')

    def testUnresolveWithoutMibLookup(self):
        cg = varbinds.NotificationOriginatorVarBinds()
        vb = cg.unmakeVarBinds(
            hlapi.SnmpEngine(),
            [(hlapi.ObjectIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)),
              hlapi.ObjectIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 5, 1)))],
            lookupMib=False
        )
        self.assertEqual(str(vb[0][0]), '1.3.6.1.6.3.1.1.4.1.0')
        self.assertEqual(str(vb[0][1]), '1.3.6.1.6.3.1.1.5.1')


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
