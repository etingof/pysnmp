
SNMP engine for Python, version 2.0.1
-------------------------------------

This is a Python implementation of SNMP v.1 engine. It's general
functionality is to assemble/disassemble SNMP v.1 message from/into
given SNMP Object IDs along with associated values. As an additional
benefit, PySNMP provides a few transport methods specific to TCP/IP
networking.

PySNMP is written entirely in Python and is self-sufficient in terms
that it does not rely on any third party tool (it is not a wrapper!).

This code is known to be used under Python interpreter versions 1.5.2,
1.6 and 2.0.

This package is distributed under terms and conditions of BSD-style
license. See the LICENSE file for details.

PRECAUTIONS
-----------

While the pure-Python MIB compiler project is underway, the ASN.1
types of Object IDs associated values must be explicitly specified
whenever user application passes values to SNMP engine.

Lack of MIB support leads to another limitation -- all the PySNMP
methods accept and report Object IDs only in dotted numeric (that is
not symbolic) representation.

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
$ tar xvf /tmp/pysnmp-2.0.1.tar
$ echo pysnmp-2.0.1 > pysnmp.pth

Alternatively, the $PYTHONPATH environment variable can be updated to
point to your PySNMP package location (assuming your UNIX shell is bash):

export PYTHONPATH=/home/ilya/src/py/pysnmp-2.0.1:$PYTHONPATH

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
>>> from pysnmp import session
>>> s = session.session ('cisco0.sovam.com', 'public')
>>> encoded_objid = s.encode_oid ([1, 3, 6, 1, 2, 1, 1, 1, 0])
>>> question = s.encode_request ('GETREQUEST', [encoded_objid], [])
>>> answer = s.send_and_receive (question)
>>> (encoded_objids, encoded_values) = s.decode_response (answer)
>>> objids = map (s.decode_value, encoded_objids)
>>> objids
['.1.3.6.1.2.1.1.1.0']
>>> values = map (s.decode_value, encoded_values)
>>> values
['Cisco Internetwork Operating System Software \015\012IOS (tm)\
5300 Software (C5300-J-M), Experimental Version 12.1(20001115:152556)\
[haag-V121_4 102]\015\012Copyright (c) 1986-2000 by cisco Systems,\
Inc.\015\012Compiled Mon 20-Nov-00 19:22 by haag']
>>> 

8X---------------- cut here --------------------

See package documentation and examples/ directory for more information
on PySNMP services.

AVAILABILITY
------------

The PySNMP software is available for download from project's homepage:
http://sourceforge.net/projects/pysnmp/

FEEDBACK
--------

I'm interested in bug reports and fixes, suggestions and improvements.
I'd be happy knowning whenever you used the PySNMP software for whatever
purpose. Please, send me a note then. Thanks!

=-=-=
mailto: ilya@glas.net
