#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
import sys

try:
    from unittest import mock

except ImportError:
    try:
        import mock

    except ImportError:
        mock = None

try:
    import unittest2 as unittest

except ImportError:
    import unittest

from tests.base import BaseTestCase

from pysnmp import hlapi
from pysnmp.hlapi import lcd
from pysnmp import debug
from pysnmp import error

if mock:

    @mock.patch('pysnmp.entity.config.addV1System', autospec=True)
    @mock.patch('pysnmp.entity.config.addV3User', autospec=True)
    @mock.patch('pysnmp.entity.config.addTargetParams', autospec=True)
    @mock.patch('pysnmp.entity.config.addTransport', autospec=True)
    @mock.patch('pysnmp.entity.config.addTargetAddr', autospec=True)
    class ConfigureCommandGeneratorTestCase(BaseTestCase):
        def setUp(self):
            self.snmpEngine = hlapi.SnmpEngine()
            self.communityData = hlapi.CommunityData('public')
            self.usmUserData = hlapi.UsmUserData('testuser', 'authkey1', 'privkey1')
            self.transportTarget = hlapi.UdpTransportTarget(('127.0.0.1', 161))

        def testCommunityData(self, mock_address, mock_transport, mock_target,
                              mock_v3user, mock_v1system):

            cfg = lcd.CommandGeneratorLcdConfigurator()
            addrName, paramsName = cfg.configure(self.snmpEngine, self.communityData,
                                                 self.transportTarget)

            self.assertTrue(addrName)
            self.assertTrue(paramsName)
            mock_v1system.assert_called_once_with(
                self.snmpEngine,
                mock.ANY,
                'public',
                None,
                mock.ANY,
                mock.ANY,
                mock.ANY
            )
            mock_v3user.assert_not_called()
            mock_target.assert_called_once_with(
                self.snmpEngine,
                mock.ANY,
                mock.ANY,
                'noAuthNoPriv',
                1
            )
            mock_transport.assert_called_once_with(
                self.snmpEngine,
                (1, 3, 6, 1, 6, 1, 1),
                mock.ANY
            )
            mock_address.assert_called_once_with(
                self.snmpEngine,
                mock.ANY,
                (1, 3, 6, 1, 6, 1, 1), ('127.0.0.1', 161),
                mock.ANY,
                100, 5,
                mock.ANY
            )

        def testUsmUserData(self, mock_address, mock_transport, mock_target,
                            mock_v3user, mock_v1system):

            cfg = lcd.CommandGeneratorLcdConfigurator()
            addrName, paramsName = cfg.configure(self.snmpEngine, self.usmUserData,
                                                 self.transportTarget)

            self.assertTrue(addrName)
            self.assertTrue(paramsName)
            mock_v1system.assert_not_called()
            mock_v3user.assert_called_once_with(
                self.snmpEngine,
                'testuser',
                (1, 3, 6, 1, 6, 3, 10, 1, 1, 2),
                'authkey1',
                (1, 3, 6, 1, 6, 3, 10, 1, 2, 2),
                'privkey1',
                None,
                securityName='testuser'
            )
            mock_target.assert_called_once_with(
                self.snmpEngine,
                mock.ANY,
                'testuser',
                'authPriv',
                3
            )
            mock_transport.assert_called_once_with(
                self.snmpEngine,
                (1, 3, 6, 1, 6, 1, 1),
                mock.ANY
            )
            mock_address.assert_called_once_with(
                self.snmpEngine,
                mock.ANY,
                (1, 3, 6, 1, 6, 1, 1), ('127.0.0.1', 161),
                mock.ANY,
                100, 5,
                mock.ANY
            )






suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
