
PYTHON SNMP FRAMEWORK
---------------------

This is a beta-quality revision of pure-Python, open source and free
implementation of v1/v2c/v3 SNMP engine.

The PySNMP project has been sponsored by a PSF grant [10]. Thanks!

FEATURES
--------

* Complete SNMPv1/v2c and SNMPv3 support
* SMI framework for resolving MIB information and implementing SMI 
  Managed Objects
* Complete SNMP entity implementation
* Extensible network transports framework (UDP and UNIX domain implemented)
* Asynchronous socket-based IO API support
* Twisted (http://twistedmatrix.com) integration
* Python eggs and py2exe friendly
* 100% Python, works with Python 1.5 though 2.x
* MT-safe

Features, specific to SNMPv3 model include:

* USM authentication (MD5/SHA) and privacy (DES/AES) protocols (RFC3414)
* View-based access control to use with any SNMP model (RFC3415)
* Built-in SNMP proxy PDU converter for building multi-lingual
  SNMP entities (RFC2576)
* Remote SNMP engine configuration
* Optional SNMP engine discovery
* Shipped with standard SNMP applications (RC3413)  

MISFEATURES
-----------

* Much slower than C implementations. Some optimization still possible.
* No pure-Python MIB compiler. But there's a workaround, read on.

INSTALLATION
------------

The PySNMP package uses distutils for package management. The PyASN1 [8]
package is required. For secure SNMPv3 communication, PyCrypto [9]
should also be installed.

OPERATION
---------

As of this writing, PySNMP implements two SNMP architectures -- the first
is a legacy one specified by SNMPv1 & v2c standards [5]. It is quite 
low-level and protocol-oriented by design. In particular, it requires
application to manage transport failures, access issues and so on.

The second model supported by PySNMP is aligned to SNMPv3 architecture, 
as specified in [4]. Here is an example on querying SNMP agent
for arbitrary value (sysDescr) over SNMP v3 with authentication and 
privacy enabled:

8X---------------- cut here --------------------

from pysnmp.entity.rfc3413.oneliner import cmdgen

userData = cmdgen.UsmUserData('test-user', 'authkey1', 'privkey1')
targetAddr = cmdgen.UdpTransportTarget(('localhost', 161))

errorIndication, errorStatus, \
                 errorIndex, varBinds = cmdgen.CommandGenerator().getCmd(
    userData, targetAddr, (('SNMPv2-MIB', 'sysDescr'), 0)
    )

if errorIndication: # SNMP engine errors
    print errorIndication
else:
    if errorStatus: # SNMP agent errors
        print '%s at %s\n' % (errorStatus, varBinds[int(errorIndex)-1])
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

While MIB parser/codegenerator has not been implemented in PySNMP, the
smidump tool of libsmi library [6] could be used for automatic convertion
of MIB text files into Python code. The produced code relies on PySNMP
SMI library.

In order to convert MIB text files into pysnmp.smi-compliant Python source,
please, use build-pysnmp-mib utility as shipped with PySNMP distribution.

A large set of pre-compiled MIB files is shipped along the pysnmp-mibs
package.[2]

AVAILABILITY
------------

The PySNMP software is freely available for download from project
homepage.[1]

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
    Use libsmi version > 0.4.5, possibly from libsmi SVN:
    svn checkout http://www.ibr.cs.tu-bs.de/svn/libsmi

[7] PySNMP mailing list archives:
    http://sourceforge.net/mail/?group_id=14735

[8] PyASN1 project homepage:
    http://pyasn1.sf.net

[9] PyCrypto project:
    http://www.amk.ca/python/code/crypto.html

[10] Python Software Foundation
    http://www.python.org/psf/

=-=-=
mailto: ilya@glas.net
