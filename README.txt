
PYTHON SNMP FRAMEWORK
---------------------

This is a pure-Python, open source and free implementation of v1/v2c/v3
SNMP engine.

The PySNMP project has been sponsored by a PSF grant [10]. Thanks!

FEATURES
--------

* Complete SNMPv1/v2c and SNMPv3 support
* SMI framework for resolving MIB information and implementing SMI 
  Managed Objects
* Complete SNMP entity implementation
* USM Extended Security Options support (3DES, 192/256-bit AES encryption)
* Extensible network transports framework (UDP/IPv4, UDP/IPv6 and UNIX domain
  sockets already implemented)
* Asynchronous socket-based IO API support
* Twisted (http://twistedmatrix.com) integration
* Python eggs and py2exe friendly
* 100% Python, works with Python 2.4 though 3.4 (alpha 3)
* MT-safe (only if run locally to a thread)

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
* No pure-Python MIB compiler. The libsmi's smidump tool used for one-time MIB compilation.

INSTALLATION
------------

The PySNMP package uses setuptools for package management. The PyASN1 [8]
package is required. For secure SNMPv3 communication, PyCrypto [9]
should also be installed.

OPERATION
---------

As of this writing, PySNMP implements two SNMP architectures -- the first
is a legacy one specified by SNMPv1 & v2c standards [5]. It is quite 
low-level and protocol-oriented by design. In particular, it requires
application to manage authentication and access issues, deal with transport
failures and similar housekeeping stuff.

The second model supported by PySNMP is aligned to SNMPv3 architecture, 
as specified in [4]. Here is an example on querying SNMP agent
for arbitrary value (sysDescr) over SNMP v3 with authentication and 
privacy enabled:

8X---------------- cut here --------------------

from pysnmp.entity.rfc3413.oneliner import cmdgen

cmdGen = cmdgen.CommandGenerator()

errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
    cmdgen.CommunityData('public'),
    cmdgen.UdpTransportTarget(('localhost', 161)),
    cmdgen.MibVariable('SNMPv2-MIB', 'sysDescr', 0),
    lookupNames=True, lookupValues=True
)

if errorIndication: # SNMP engine errors
    print errorIndication
else:
    if errorStatus: # SNMP agent errors
        print '%s at %s\n' % (
              errorStatus.prettyPrint(),
              errorIndex and varBinds[int(errorIndex)-1] or '?')
            )
    else:
        for oid, val in varBinds: # SNMP agent values
            print '%s = %s' % (oid.prettyPrint(), val.prettyPrint())

8X---------------- cut here --------------------

For more examples, please see the examples directory in the PySNMP distribution.

MIB SUPPORT
-----------

The pysnmp.smi package component defines and implements data model for SNMP SMI
objects. With that model, various objects defined in MIB file could be
implemented in Python, loaded into SNMP entity and used for verification and
visualisation purposes (SNMP manager side) and/or become management targets
(SNMP agent side).

While MIB parser/codegenerator has not yet been implemented in PySNMP, the
smidump tool of libsmi library [6] could be used for automatic, one-time 
convertion of MIB text files into specific Python programs designed to be
dynamically loaded and used by PySNMP engine.

To simplify smidump tool invocation followed by libsmi2pysnmp script, PySNMP
distribution includes a build-pysnmp-mib shell script. You should use it for
one-time MIB text modules convertion into PySNMP format.

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

[9] PyCrypto package:
    http://pycrypto.org

[10] Python Software Foundation
    http://www.python.org/psf/

=-=-=
mailto: ilya@glas.net
