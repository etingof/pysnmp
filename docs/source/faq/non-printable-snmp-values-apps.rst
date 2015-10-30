
Garbaged SNMP values (apps)
---------------------------

Q. When my PySNMP application prints out fetched values, some of them 
   come out as a garbage on my screan. Here's my code:

.. code-block:: python

    for varBind in varBinds:
      print(' = '.join([ str(x) for x in varBind ])

   and the result is:

.. code-block:: python

    1.3.6.1.4.1.161.19.3.2.1.63.0 = 50000
    1.3.6.1.4.1.161.19.3.2.1.4.0 = '\x01\x02\x03\x04'

   The IpAddress type seems to be the only one with this problem.

A. Always use prettyPrint() method for all pyasn1-based objects -- it 
   automatically converts ASN1 types to human-friendly form.

.. code-block:: python

    > > > from pysnmp.proto import rfc1902
    > > > a = rfc1902.IpAddress('1.2.3.4')
    > > > str(a)
    '\x01\x02\x03\x04'
    > > > a
    IpAddress('1.2.3.4')
    > > > a.prettyPrint()
    '1.2.3.4'
    > > > rfc1902.IpAddress.prettyPrint(a)
    '1.2.3.4'

See `pyasn1 tutorial <http://pyasn1.sourceforge.net/>`_ for more information
on pyasn1 data model.

