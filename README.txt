
SNMP framework for Python, version 4.x
--------------------------------------

This is a pure-Python implementation of multi-protocol SNMP engine. At the
time of this writing, only SNMP protocol version 1 and 2c are fully 
supported. However, this framework is designed along the lines of SNMPv3
architecture [1], so it should seamlessly host SNMP version 3, and hopefully
future SNMP versions, whenever corresponding protocol-specific modules
would be implemented (work's in progress).

The basic features of SNMP engine include SNMP messages processing and
exchange between processes, as well as MIB information access and MIB
instrumentation management.

PySNMP is written entirely in Python and is self-sufficient (it is not a 
wrapper!).

The PySNMP package is distributed under terms and conditions of BSD-style
license. See LICENSE at PySNMP homepage [2].

FEATURES
--------

* Complete SNMPv1 and SNMPv2c support
* Complete SNMP entity implementation (SNMP manager and agent roles)
* SMI framework for looking up MIB information and managing MIB 
  instrumentation
* Multiple network transport methods (UDP and UNIX domain at the moment)
* Both synchronous and asynchronous socket-based IO API support
* 100% Python, works with Python 1.5 and later
* MT-safe

MISFEATURES
-----------

* No pure-Python MIB compiler. However, there's a tools/libsmi2pysnmp 
  script in the PySNMP distribution which may be used for converting MIB
  text files into pysnmp's SMI-compliant Python modules. There's also a
  large set of pre-compiled MIB files in the pysnmp-mibs package [3].
* No SNMP v.3 support

PRECAUTIONS
-----------

The 4.x revision of PySNMP brings an alpha-quality code, unstable APIs and
appears to run really slow. Also, the 4.x APIs are quite incompatible
with their 2.x/3.x counterparts as of this early release. Chances are that,
at least, high-level compatibility interfaces would appear by stable
releases.

INSTALLATION
------------

The PySNMP package uses distutils for installation:

$ tar zxf pysnmp-4.0.0.tar.gz
$ cd pysnmp-4.0.0
$ python setup.py install

TESTING
-------

Once the PySNMP package is installed, try running:

python -c 'from pysnmp.test import suite; suite.run()'

at your command line to make sure the whole thing is working
properly. Otherwise, please, report all failures to PySNMP mailing
list (see below).

OPERATION
---------

As of this writing, PySNMP implements two SNMP architectures -- the first
is a legacy one used in SNMPv1 & v2c specifications [4]. It is quite 
protocol-oriented and, in particular, requires application to manage
transport failures, MIB access issues and so on.

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
as specified by [1]. The model is somewhat complex for this introductory
README, so for more information, please, follow the pysnmp/examples 
directory at the PySNMP distribution.

MIB SUPPORT
-----------


AVAILABILITY
------------

The PySNMP software is available for download from project's homepage. [2]

GETTING HELP
------------

If something does not work as expected, please, try browsing PySNMP
mailing list archives at http://sourceforge.net/mail/?group_id=14735
or post your question there.

FEEDBACK
--------

I'm interested in bug reports and fixes, suggestions and improvements.
I'd be happy knowning whenever you used the PySNMP software for whatever
purpose. Please, send me a note then. Thanks!

REFERENCES
----------

[1] SNMP Version 3 specification and related
    http://www.ibr.cs.tu-bs.de/projects/snmpv3/

[2] SNMP Version 1/2 specifications


[2] libsmi homepage

[2] PySNMP project homepage:
    http://pysnmp.sf.net

[4] PySNMP mailing list archives:
    http://sourceforge.net/mail/?group_id=14735

[3] Pre-compiled MIB files:
    http://sourceforge.net/project/showfiles.php?group_id=14735


=-=-=
mailto: ilya@glas.net
