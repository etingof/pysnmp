
SNMP framework for Python, version 4.x (alpha)
----------------------------------------------

This is a pure-Python implementation of multi-protocol SNMP engine. Although
only SNMP versions 1 and 2c are fully supported at the moment, the APIs
are aligned with the SNMPv3 architecture [4], so it would naturally host SNMP 
version 3, and hopefully future SNMP versions, whenever corresponding 
protocol-specific modules would be implemented (work's in progress).

This software provides facilities for building pure-Python SNMP v1/v2c entities,
such as managers, agents and proxies. A set of MIB data access methods allows for
building SNMP managers fully aware of agent MIB, as well as SNMP agents having
their own MIB instrumentation.

PySNMP is written entirely in Python and is self-sufficient (it is not a 
wrapper!).

The PySNMP package is distributed under terms and conditions of BSD-style
license. See LICENSE at PySNMP homepage [1].

WARNING! WARNING! WARNING!
--------------------------

The 4.x branch of PySNMP is extremely experimental, the API WILL
change in the future. Do not use the 4.x API in real projects!

FEATURES
--------

* Complete SNMPv1 and SNMPv2c support
* Complete SNMP entity implementation (SNMP manager and agent roles)
* SMI framework for browsing MIB information and managing MIB instrumentation
* Extensible network transports framework (UDP and UNIX domain implemented)
* Asynchronous socket-based IO API support
* 100% Python, works with Python 1.5 and later
* MT-safe

MISFEATURES
-----------

* No pure-Python MIB compiler. Although, there's a workaround, read on.
* No SNMP v.3 support

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

OPERATION
---------

As of this writing, PySNMP implements two SNMP architectures -- the first
is a legacy one used in SNMPv1 & v2c specifications [5]. It is quite 
protocol-oriented and, in particular, requires application to manage
transport failures, access issues and so on.

Here is an example on querying an SNMP agent (cisco router) for arbitrary
value (sysDescr):

8X---------------- cut here --------------------

from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp.carrier.asynsock.dgram.udp import UdpSocketTransport
from pysnmp.proto.api import alpha

ver = alpha.protoVersions[alpha.protoVersionId1]

def cbRecvFun(tspDsp, transportDomain, transportAddress, wholeMsg):
    rsp = ver.Message()
    rsp.berDecode(wholeMsg)
    for varBind in rsp.apiAlphaGetPdu().apiAlphaGetVarBindList():
        print varBind.apiAlphaGetOidVal()
    tspDsp.doDispatchFlag = 0
    return ''
 
req = ver.Message()
req.apiAlphaSetCommunity('public')
req.apiAlphaSetPdu(ver.GetRequestPdu())
req.apiAlphaGetPdu().apiAlphaSetVarBindList(
    ((1,3,6,1,2,1,1,1,0), ver.Null())
)

tspDsp = AsynsockDispatcher(udp=UdpSocketTransport().openClientMode())
tspDsp.registerRecvCbFun(cbRecvFun)
tspDsp.sendMessage(req.berEncode(), 'udp', ('router-1.glas.net', 161))
tspDsp.runDispatcher(liveForever=1)

8X---------------- cut here --------------------

The second model supported by PySNMP resembles the SNMPv3 architecture, 
as specified in [4]. The model is somewhat complex for this introductory
README, so for more information, please, follow the pysnmp/examples/v3arch 
directory in the PySNMP distribution.

A set of complete SNMP applications based on the PySNMP framework's
shipped with the pysnmp-apps package. [3]

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

=-=-=
mailto: ilya@glas.net
