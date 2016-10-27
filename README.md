
SNMP library for Python
-----------------------
[![Downloads](https://img.shields.io/pypi/dm/pysnmp.svg)](https://pypi.python.org/pypi/pysnmp)
[![PyPI](https://img.shields.io/pypi/v/pysnmp.svg?maxAge=2592000)](https://pypi.python.org/pypi/pysnmp)
[![Python Versions](https://img.shields.io/pypi/pyversions/doxygen-junit.svg)](https://pypi.python.org/pypi/doxygen-junit/)
[![Build status](https://travis-ci.org/etingof/pysnmp.svg?branch=master)](https://secure.travis-ci.org/etingof/pysnmp)
[![GitHub license](https://img.shields.io/badge/license-BSD-blue.svg)](https://raw.githubusercontent.com/etingof/pysnmp/master/LICENSE.txt)

This is a pure-Python, open source and free implementation of v1/v2c/v3
SNMP engine distributed under 2-clause [BSD license](http://pysnmp.sourceforge.net/license.html).

The PySNMP project was initially sponsored by a [PSF](http://www.python.org/psf/) grant.
Thank you!

Features
--------

* Complete SNMPv1/v2c and SNMPv3 support
* SMI framework for resolving MIB information and implementing SMI
  Managed Objects
* Complete SNMP entity implementation
* USM Extended Security Options support (3DES, 192/256-bit AES encryption)
* Extensible network transports framework (UDP/IPv4, UDP/IPv6 and UNIX domain
  sockets already implemented)
* Asynchronous socket-based IO API support
* [Twisted](http://twistedmatrix.com), [Asyncio](https://docs.python.org/3/library/asyncio.html)
  and [Trollius](http://trollius.readthedocs.org/index.html) integration
* [PySMI](http://pysmi.sf.net) integration for dynamic MIB compilation
* Python eggs and py2exe friendly
* 100% Python, works with Python 2.4 though 3.5
* MT-safe (only if run locally to a thread)

Features, specific to SNMPv3 model include:

* USM authentication (MD5/SHA) and privacy (DES/AES) protocols (RFC3414)
* View-based access control to use with any SNMP model (RFC3415)
* Built-in SNMP proxy PDU converter for building multi-lingual
  SNMP entities (RFC2576)
* Remote SNMP engine configuration
* Optional SNMP engine discovery
* Shipped with standard SNMP applications (RC3413)

Download
--------

The PySNMP software is freely available for download from [PyPI](https://pypi.python.org/pypi/pysnmp)
and [project site](http://pysnmp.sf.net/download.html).

Installation
------------

Just run:

```bash
$ pip install pysnmp
```
    
to download and install PySNMP along with its dependencies:

* [PyASN1](http://pyasn1.sf.net)
* [PyCrypto](http://pycrypto.org) (required only if SNMPv3 encryption is in use)
* [PySMI](http://pysmi.sf.net) (required for MIB services only)

Besides the library, command-line [SNMP utilities](https://github.com/etingof/pysnmp-apps)
written in pure-Python could be installed via:

```bash
$ pip install pysnmp-apps
```
    
and used in the very similar manner as conventional Net-SNMP tools:

```bash
$ snmpget.py -v3 -l authPriv -u usr-md5-des -A authkey1 -X privkey1 demo.snmplabs.com sysDescr.0
SNMPv2-MIB::sysDescr.0 = DisplayString: SunOS zeus.snmplabs.com 4.1.3_U1 1 sun4m 
```
    
Examples
--------

PySNMP is designed highly modular and implements many programming interfaces. Most
high-level and easy to use API is called *hlapi* and can be used like this:

```python
from pysnmp.hlapi import *

iterator = getCmd(SnmpEngine(),
                  CommunityData('public'),
                  UdpTransportTarget(('demo.snmplabs.com', 161)),
                  ContextData(),
                  ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))

errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

if errorIndication:  # SNMP engine errors
    print(errorIndication)
else:
    if errorStatus:  # SNMP agent errors
        print('%s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex)-1] if errorIndex else '?'))
    else:
        for varBind in varBinds:  # SNMP response contents
            print(' = '.join([x.prettyPrint() for x in varBind]))
```

or, to send SNMP TRAP:

```python
from pysnmp.hlapi import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    sendNotification(
        SnmpEngine(OctetString(hexValue='8000000001020304')),
        UsmUserData('usr-sha-aes128', 'authkey1', 'privkey1',
                    authProtocol=usmHMACSHAAuthProtocol,
                    privProtocol=usmAesCfb128Protocol),
        UdpTransportTarget(('demo.snmplabs.com', 162)),
        ContextData(),
        'trap',
        NotificationType(ObjectIdentity('SNMPv2-MIB', 'authenticationFailure'))
    )
)

if errorIndication:
    print(errorIndication)
```

We maintain publicly available SNMP Agent and TRAP sink at 
[demo.snmplabs.com](http://snmpsim.sourceforge.net/public-snmp-simulator.html). You are
welcome to play with it while experimenting with your PySNMP scripts.

```bash
$ python3 examples/hlapi/asyncore/sync/manager/cmdgen/usm-sha-aes128.py
SNMPv2-MIB::sysDescr.0 = SunOS zeus.snmplabs.com 4.1.3_U1 1 sun4m
$
$ python3 examples//hlapi/asyncore/sync/agent/ntforg/v3-inform.py
SNMPv2-MIB::sysUpTime.0 = 0
SNMPv2-MIB::snmpTrapOID.0 = SNMPv2-MIB::warmStart
SNMPv2-MIB::sysName.0 = system name
```
    
Other than that, PySNMP is capable to automatically fetch required MIBs from HTTP, FTP sites
or local directories. You could configure any MIB source available to you (including
[this one](http://mibs.snmplabs.com/asn1/)) for that purpose.

For more example scripts please refer to [examples section](http://pysnmp.sourceforge.net/examples/contents.html#high-level-snmp)
at pysnmp web site.

Documentation
-------------

Detailed information on SNMP design, history as well as PySNMP programming interfaces could
be found at [pysnmp site](http://pysnmp.sf.net/docs/tutorial.html).

Getting help
------------

If something does not work as expected, try browsing PySNMP
[mailing list archives](http://sourceforge.net/mail/?group_id=14735) or post
your question [to Stack Overflow](http://stackoverflow.com/questions/ask).

Feedback and collaboration
--------------------------

I'm interested in bug reports, fixes, suggestions and improvements. Your
pull requests are very welcome!

Copyright (c) 2005-2016, [Ilya Etingof](http://ilya@glas.net). All rights reserved.
