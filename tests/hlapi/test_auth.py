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


class ProtocolConstantsTestCase(BaseTestCase):
    def testEnsureProtocols(self):
        self.assertTrue(hasattr(hlapi, 'usm3DESEDEPrivProtocol'))
        self.assertTrue(hasattr(hlapi, 'usm3DESEDEPrivProtocol'))
        self.assertTrue(hasattr(hlapi, 'usmAesCfb128Protocol'))
        self.assertTrue(hasattr(hlapi, 'usmAesCfb192Protocol'))
        self.assertTrue(hasattr(hlapi, 'usmAesCfb256Protocol'))
        self.assertTrue(hasattr(hlapi, 'usmAesBlumenthalCfb192Protocol'))
        self.assertTrue(hasattr(hlapi, 'usmAesBlumenthalCfb256Protocol'))
        self.assertTrue(hasattr(hlapi, 'usmDESPrivProtocol'))
        self.assertTrue(hasattr(hlapi, 'usmHMACMD5AuthProtocol'))
        self.assertTrue(hasattr(hlapi, 'usmHMACSHAAuthProtocol'))
        self.assertTrue(hasattr(hlapi, 'usmHMAC128SHA224AuthProtocol'))
        self.assertTrue(hasattr(hlapi, 'usmHMAC192SHA256AuthProtocol'))
        self.assertTrue(hasattr(hlapi, 'usmHMAC256SHA384AuthProtocol'))
        self.assertTrue(hasattr(hlapi, 'usmHMAC384SHA512AuthProtocol'))
        self.assertTrue(hasattr(hlapi, 'usmNoAuthProtocol'))
        self.assertTrue(hasattr(hlapi, 'usmNoPrivProtocol'))


class CommunityDataTestCase(BaseTestCase):
    def testVersionOne(self):
        auth = hlapi.CommunityData(
            'public', mpModel=0, contextEngineId='0123456789', contextName='abc', tag='x'
        )
        self.assertTrue(auth.communityIndex)
        self.assertEqual(auth.communityName, 'public')
        self.assertEqual(auth.contextEngineId, '0123456789')
        self.assertEqual(auth.contextName, 'abc')
        self.assertEqual(auth.mpModel, 0)
        self.assertEqual(auth.securityLevel, 'noAuthNoPriv')
        self.assertEqual(auth.securityModel, 1)
        self.assertTrue(auth.securityName)
        self.assertEqual(auth.tag, 'x')

    def testVersionTwoC(self):
        auth = hlapi.CommunityData(
            'public', contextEngineId='0123456789', contextName='abc', tag='x'
        )
        self.assertTrue(auth.communityIndex)
        self.assertEqual(auth.communityName, 'public')
        self.assertEqual(auth.contextEngineId, '0123456789')
        self.assertEqual(auth.contextName, 'abc')
        self.assertEqual(auth.mpModel, 1)
        self.assertEqual(auth.securityLevel, 'noAuthNoPriv')
        self.assertEqual(auth.securityModel, 2)
        self.assertTrue(auth.securityName)
        self.assertEqual(auth.tag, 'x')

    def testClone(self):
        auth = hlapi.CommunityData('public').clone('private')
        self.assertTrue(auth.communityIndex)
        self.assertEqual(auth.communityName, 'private')
        self.assertEqual(auth.contextEngineId, None)
        self.assertEqual(auth.contextName, hlapi.OctetString(''))
        self.assertEqual(auth.mpModel, 1)
        self.assertEqual(auth.securityLevel, 'noAuthNoPriv')
        self.assertEqual(auth.securityModel, 2)
        self.assertTrue(auth.securityName)
        self.assertEqual(auth.tag, hlapi.OctetString(''))


class UsmUserDataTestCase(BaseTestCase):
    def testAuthPrivDefaults(self):
        auth = hlapi.UsmUserData('testuser', 'authkey1', 'privkey1')
        self.assertEqual(auth.authKey, 'authkey1')
        self.assertEqual(auth.authProtocol, (1, 3, 6, 1, 6, 3, 10, 1, 1, 2))
        self.assertEqual(auth.mpModel, 3)
        self.assertEqual(auth.privKey, 'privkey1')
        self.assertEqual(auth.privProtocol, (1, 3, 6, 1, 6, 3, 10, 1, 2, 2))
        self.assertFalse(auth.securityEngineId)
        self.assertEqual(auth.securityLevel, 'authPriv')
        self.assertEqual(auth.securityModel, 3)
        self.assertEqual(auth.securityName, 'testuser')
        self.assertEqual(auth.userName, 'testuser')

    def testAuthNoPrivDefaults(self):
        auth = hlapi.UsmUserData('testuser', 'authkey1')
        self.assertEqual(auth.authKey, 'authkey1')
        self.assertEqual(auth.authProtocol, (1, 3, 6, 1, 6, 3, 10, 1, 1, 2))
        self.assertEqual(auth.mpModel, 3)
        self.assertFalse(auth.privKey)
        self.assertEqual(auth.privProtocol, (1, 3, 6, 1, 6, 3, 10, 1, 2, 1))
        self.assertFalse(auth.securityEngineId)
        self.assertEqual(auth.securityLevel, 'authNoPriv')
        self.assertEqual(auth.securityModel, 3)
        self.assertEqual(auth.securityName, 'testuser')
        self.assertEqual(auth.userName, 'testuser')

    def testNoAuthNoPrivDefaults(self):
        auth = hlapi.UsmUserData('testuser')
        self.assertFalse(auth.authKey)
        self.assertEqual(auth.authProtocol, (1, 3, 6, 1, 6, 3, 10, 1, 1, 1))
        self.assertEqual(auth.mpModel, 3)
        self.assertFalse(auth.privKey)
        self.assertEqual(auth.privProtocol, (1, 3, 6, 1, 6, 3, 10, 1, 2, 1))
        self.assertFalse(auth.securityEngineId)
        self.assertEqual(auth.securityLevel, 'noAuthNoPriv')
        self.assertEqual(auth.securityModel, 3)
        self.assertEqual(auth.securityName, 'testuser')
        self.assertEqual(auth.userName, 'testuser')

    def testAuthPriv(self):
        auth = hlapi.UsmUserData('testuser', 'authkey1', 'privkey1',
                                 authProtocol=hlapi.usmHMACSHAAuthProtocol,
                                 privProtocol=hlapi.usmAesCfb256Protocol)
        self.assertEqual(auth.authKey, 'authkey1')
        self.assertEqual(auth.authProtocol, (1, 3, 6, 1, 6, 3, 10, 1, 1, 3))
        self.assertEqual(auth.mpModel, 3)
        self.assertEqual(auth.privKey, 'privkey1')
        self.assertEqual(auth.privProtocol, (1, 3, 6, 1, 4, 1, 9, 12, 6, 1, 102))
        self.assertFalse(auth.securityEngineId)
        self.assertEqual(auth.securityLevel, 'authPriv')
        self.assertEqual(auth.securityModel, 3)
        self.assertEqual(auth.securityName, 'testuser')
        self.assertEqual(auth.userName, 'testuser')


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
