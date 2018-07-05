#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
try:
    import unittest2 as unittest

except ImportError:
    import unittest

suite = unittest.TestLoader().loadTestsFromNames(
    ['tests.test_debug.suite',
     'tests.hlapi.test_auth.suite',
     'tests.hlapi.test_context.suite',
     'tests.hlapi.test_varbinds.suite',

     ]
)


if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
