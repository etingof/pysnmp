
SNMP framework for Python, version 4.x (alpha)
----------------------------------------------

This is a pure-Python implementation of multi-protocol SNMP engine.

This software provides facilities for building pure-Python SNMP v1/v2c/v3 entities,
such as managers, agents and proxies. A set of MIB data access methods allows for
building SNMP managers fully aware of agent MIB, as well as SNMP agents having
their own MIB instrumentation.

PySNMP is written entirely in Python and only requires a few third-party
Python packages to operate.

The PySNMP package is distributed under terms and conditions of BSD-style
license. See LICENSE at PySNMP homepage [1].

WARNING! WARNING! WARNING!
--------------------------

The 4.x branch of PySNMP is extremely experimental, the API WILL
change in the future. Do not use the 4.x API in real projects!

FEATURES
--------

* Complete SNMPv1/v2c and SNMPv3 support
* Complete SNMP entity implementation (SNMP manager and agent roles)
* SMI framework for browsing MIB information and managing MIB instrumentation
* Extensible network transports framework (UDP and UNIX domain implemented)
* Asynchronous socket-based IO API support
* 100% Python, works with Python 1.5 and later
* MT-safe

MISFEATURES
-----------

* No pure-Python MIB compiler. Although, there's a workaround, read on.

PRECAUTIONS
-----------

The 4.x revision of PySNMP brings an alpha-quality code, unstable APIs and
appears to run painfully slow. Also, the 4.x APIs are quite incompatible
with their 2.x/3.x counterparts as of this early release. Chances are that,
at least, high-level compatibility interfaces would appear in future stable
releases.

INSTALLATION
------------

The PySNMP package uses distutils for installation:

$ tar zxf pysnmp.tar.gz
$ cd pysnmp
$ python setup.py install

Besides PySNMP, the pyasn1 [8] package must be installed. For secure SNMPv3 
operation, the PyCrypto [9] toolkit is required.

OPERATION
---------

As of this writing, PySNMP implements two SNMP architectures -- the first
is a legacy one used in SNMPv1 & v2c specifications [5]. It is quite 
protocol-oriented and, in particular, requires application to manage
transport failures, access issues and so on.

The second model supported by PySNMP resembles the SNMPv3 architecture, 
as specified in [4]. Here is an example on querying SNMP agent
for arbitrary value (sysDescr) over SNMP v3 with authentication and 
privacy enabled:

8X---------------- cut here --------------------

from pysnmp.entity.rfc3413.oneliner import cmdgen

userData = cmdgen.UsmUserData('test-user', 'authkey1', 'privkey1')
targetAddr = cmdgen.UdpTransportTarget(('localhost', 161))

errorIndication, errorStatus, errorIndex, varBinds = cmdgen.CmdGen().getCmd(
    userData, targetAddr, (('sysDescr', 'SNMPv2-MIB'), 0)
    )

if errorIndication: # SNMP engine errors
    print errorIndication
else:
    if errorStatus: # SNMP agent errors
        print '%s at %s\n' % (errorStatus, varBinds[errorIndex-1])
    else:
        for varBind in varBinds: # SNMP agent values
            print '%s = %s' % varBind

8X---------------- cut here --------------------

For more examples, please see the examples directory in the PySNMP distribution.

MIB SUPPORT
-----------

The pysnmp.smi sub-package defines and implements data model for SNMP SMI
objects. With that model, various objects defined in MIB file could be
implemented in Python, loaded into SNMP entity and used for verification and
visualisation purposes (SNMP manager side) and/or become management targets
(SNMP agent side).

Since PySNMP native MIB compiler/codegenerator is not yet implemented,
the Python dump feature of libsmi library [6] is used. In order to convert MIB
text files into pysnmp.smi-compliant Python source, something like the
following UNIX shell script could be used:

for srcfile in /usr/share/snmp/mibs/*txt
do
    dstmib=`echo $srcfile | sed -e 's/\.txt//g'`.py
    smidump -f python $srcfile | libsmi2pysnmp > $dstmib
done

The libsmi2pysnmp script is could be found in pysnmp/tools/ directory.

Alternatively, a large set of pre-compiled MIB files is shipped along the
pysnmp-mibs package. [2]

AVAILABILITY
------------

The PySNMP software is freely available for download from project's homepage.[1]

GETTING HELP
------------

If something does not work as expected, please, try browsing PySNMP
mailing list archives or post your question there. [7]

FEEDBACK
--------

I'm interested in bug reports and fixes, suggestions and improvements.
I'd be happy knowning whenever you used the PySNMP software for whatever
purpose. Please, send me a note then. Thanks!

REFERENCES
----------

[1] PySNMP project homepage:
    http://pysnmp.sf.net

[2] Pre-compiled PySNMP MIB modules:
    http://sourceforge.net/project/showfiles.php?group_id=14735

[3] PySNMP applications:
    http://sourceforge.net/project/showfiles.php?group_id=14735

[4] SNMP Version 3 specification and related
    http://www.ibr.cs.tu-bs.de/projects/snmpv3/

[5] SNMP Version 1/2 specifications:
    http://www.ietf.org/rfc/rfc1155.txt - http://www.ietf.org/rfc/rfc1158.txt
    http://www.ietf.org/rfc/rfc1901.txt - http://www.ietf.org/rfc/rfc1909.txt

[6] libsmi homepage
    http://www.ibr.cs.tu-bs.de/projects/libsmi/

[7] PySNMP mailing list archives:
    http://sourceforge.net/mail/?group_id=14735

[8] pyasn1 project homepage:
    http://pyasn1.sf.net

[9] PyCrypto project:
    http://www.amk.ca/python/code/crypto.html

=-=-=
mailto: ilya@glas.net
