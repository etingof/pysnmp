
SNMP engine for Python, version 3.x
-----------------------------------

This is a Python implementation of SNMP v.1/v.2c engine. Its general
functionality is to assemble/disassemble SNMP messages from/into
given SNMP Object IDs along with associated values. PySNMP also provides
a few transport methods specific to TCP/IP networking.

PySNMP is written entirely in Python and is self-sufficient in terms
that it does not rely on any third party tool (it is not a wrapper!).

The PySNMP package is distributed under terms and conditions of BSD-style
license. See the LICENSE file for details.

FEATURES
--------

* Complete SNMPv1 and SNMPv2c support
* Seamless SNMP manager and agent roles support
* Both synchronous and asynchronous IO API support
* Fully documented API with many examples
* Generic, objective ASN.1 framework
* Partial MIB I/II data types and macros implementation (check
  CVS at SF for recent development)
* 100% Python, works with Python 1.x and later
* MT-safe

MISFEATURES
-----------

* No MIB compiler (though, it's possible to compile ASN.1 code into PySNMP
  classes by hand, oh...)
* No SNMP v.3 support (though, it's almost implemented, check CVS at SF)

PRECAUTIONS
-----------

For notes on backward compatibility with previous PySNMP revisions, please,
refer to the COMPATIBILITY file in the PySNMP distribution.

Since MIB support is not integrated into PySNMP package at the moment, this
software accept and report Object IDs only in a non-symbolic (dotted) notation.

INSTALLATION
------------

You might try distutils to install PySNMP by just typing:

$ python setup.py install

This should work on Unix and Microsoft Windows. Alternatively you can
install PySNMP by hand:

On UNIX, the pysnmp package can be put into the python/site-packages/
directory in the following way (assuming your Python distribution
resides under /usr/local/lib/python):

$ cd /usr/local/lib/python/site-packages
$ tar xvf /tmp/pysnmp-3.3.1.tar
$ echo pysnmp-3.3.1 > pysnmp.pth

Alternatively, the $PYTHONPATH environment variable can be updated to
point to your PySNMP package location (assuming your UNIX shell is bash):

export PYTHONPATH=/home/ilya/src/py/pysnmp-3.3.1:$PYTHONPATH

The latter trick is also known to work on Windows.

I've been told, that on Windows 2000, one needs to go to "Control panel"
-> "System" -> "Advanced" -> "Environment variables" and add/update the
PYTHONPATH environment variable there.

OPERATION
---------

Here is an example of using pysnmp package for querying SNMP agent
(cisco router) for arbitrary value.

8X---------------- cut here --------------------

Python 1.5.2 (#3, Aug 25 1999, 19:14:24)  [GCC 2.8.1] on sunos5
Copyright 1991-1995 Stichting Mathematisch Centrum, Amsterdam
>>> from pysnmp.proto import v1
>>> from pysnmp.proto.api import generic
>>> from pysnmp.mapping.udp import role
>>> req = v1.GetRequest()
>>> req.apiGenGetPdu().apiGenSetVarBind([('1.3.6.1.2.1.1.1.0', v1.Null())])
>>> tr = role.manager(('router-1.glas.net', 161))
>>> (answer, src) = tr.send_and_receive(req.encode())
>>> rsp = v1.GetResponse()
>>> rsp.decode(answer)
>>> vars = rsp.apiGenGetPdu().apiGenGetVarBind()
>>> print vars
[('.1.3.6.1.2.1.1.1.0', OctetString('Cisco Internetwork Operating System Software \015\012IOS (tm) 5400 Software(C5400-JS-M), Version 12.2(11.8b), MAINTENANCE INTERIM SOFTWARE\015\012 Copyright (c) 1986-2002 by cisco Systems, Inc.\015\012Compiled Tue 30-Jul-02 19:02 by pwade'))]

8X---------------- cut here --------------------

See package documentation and examples/ directory for more information
on PySNMP services.

AVAILABILITY
------------

The PySNMP software is available for download from project's homepage:
http://sourceforge.net/projects/pysnmp/

GETTING HELP
------------

Once anything does not work as expected, please, try browsing PySNMP
mailing list archives at http://sourceforge.net/mail/?group_id=14735
or post your question there.

FEEDBACK
--------

I'm interested in bug reports and fixes, suggestions and improvements.
I'd be happy knowning whenever you used the PySNMP software for whatever
purpose. Please, send me a note then. Thanks!

=-=-=
mailto: ilya@glas.net
