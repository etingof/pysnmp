SNMP manager module for Python, version 1.3.14
----------------------------------------------

This is a simple Python implementation of SNMP V1 manager. It is written
entirely in Python.

This package is distributed under terms and conditions of BSD license. See
LICENSE file shipped along with this package for details.


PRECAUTIONS
-----------

SNMP traps are not fully implemented yet.

MIB parsing's not implemented hence values of Object-Id's need to be
encoded by the application when it's calling PySNMP module to transmit
SNMP packets.


OPERATION
---------

---- cut here ---

# import SNMP module
import pysnmp

# OBJID to lookup
OBJID = '.1.3.6.1.4.1.307.3.2.1.1.1.4.1'

# initialize lists of BER encoded OBJID's and their values to lookup
encoded_oids = []
encoded_vals = []

# create SNMP session object
session = pysnmp.session(agent='pm16.glasnet.ru', community='mycomm')

# encode an objid
encoded_oids.append(session.encode_oid(session.str2nums(OBJID)))

# build SNMP packet to be sent
packet = session.encode_request ('GETREQUEST', encoded_oids, encoded_vals)

# send SNMP request and receive a response
response = session.send_and_receive (packet)

# parse a response packet
(encoded_oids, encoded_vals) = session.decode_response (response, 'GETRESPONSE')

# decode and print OID/value pair
print session.decode_value(encoded_oids[0]),
print ' --> ',
print session.decode_value(encoded_vals[0])

--- cut here ---

See examples/ directory for more examples.


AVAILABILITY
------------

PySNMP is a free software. Recent versions of this package's available from
ftp://ftp.glas.net/users/ilya/tools/pysnmp/pysnmp.tar.gz


FEEDBACK
--------

I'm interested in bug reports & fixes, suggestions and improvements. Also,
I'd be happy knowning about your software development projects where you
used my PySNMP module. Please, send me a note about that.

Thanks!

=-=-=
This document and the PySNMP module was written by Ilya Etingof <ilya@glas.net>
