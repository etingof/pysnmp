
Ignored SNMP packets
--------------------

Q. Some network devices do not respond to PySNMP-based management 
   requests for particular OIDs.

.. code-block:: bash

   $ pysnmpget -v2c -c public 10.0.0.33 1.3.6.1.2.1.2.2.1.10.3
   SNMPv2-SMI::mib-2.2.2.1.10.3 = Counter32: 1519568842
   $ snmpget.py -v2c -c public 10.0.0.33 1.3.6.1.2.1.2.2.1.10.4
   requestTimedOut

   Meanwhile, tcpcump shows request-response sequence:

.. code-block:: bash

   13:33:30.161843 IP 10.0.0.33.snmp > 10.0.0.1.51094: 
   GetResponse(31)  interfaces.ifTable.ifEntry.ifInOctets.3=1532504859
   13:33:30.161881 IP 10.0.0.33.snmp > 10.0.0.1.51094: 
   GetResponse(31)  interfaces.ifTable.ifEntry.ifInOctets.3=1532504859

   In some cases, particularily when running v1arch PySNMP code, the 
   following exception may be thrown on response processing:

.. code-block:: python

   Traceback (most recent call last):
   ....
   File "build/bdist.linux-i686/egg/pyasn1/type/base.py", line 64, in
  __init__
   File "build/bdist.linux-i686/egg/pyasn1/type/base.py", line 32, in _verifySubtypeSpec
   File "build/bdist.linux-i686/egg/pyasn1/type/constraint.py", line 33, in __call__
   pyasn1.type.error.ValueConstraintError: ConstraintsIntersection(ConstraintsIntersection(), ValueRangeConstraint(0, 4294967295)) failed at: ValueRangeConstraint(0, 4294967295) failed at: -1413698940

A. This appears to be a [widespread] bug in BER integer encoders. It usually 
   gets noticed on Counter values as they are constrained to be positive while 
   wrong encoding yelds them negative.

   Here's broken encoding:

.. code-block:: python

   >>> decoder.decode('A\x04\xab\xbc\xaa\x84', asn1Spec=rfc1155.Counter())
   Traceback (most recent call last):
   ...
   pyasn1.type.error.ValueConstraintError: ConstraintsIntersection(ConstraintsIntersection(), ValueRangeConstraint(0, 4294967295)) failed at: ValueRangeConstraint(0, 4294967295) failed at: -1413698940

And here's a good one:

.. code-block:: python

   >>> decoder.decode('A\x05\x00\xab\xbc\xaa\x84',
   >>> asn1Spec=rfc1155.Counter())
   (Counter('2881268356'), '')

   Notice the third octet -- positive values must have its highest bit set 
   to zero.

   Here's an example hack that converts negated values into their positive 
   complimentaries for Counter type.

.. code-block:: python

   from pysnmp.proto import rfc1155, rfc1902, api
   from pyasn1.codec.ber import encoder, decoder

   # --- hack Counter type

   def counterCloneHack(self, *args):
       if args and args[0] < 0:
           args = (0xffffffff+args[0]-1,) + args[1:]

       return self.__class__(*args)

   rfc1155.Counter.clone = counterCloneHack
   rfc1902.Counter32.clone = counterCloneHack

   Execute this hack before any SNMP message processing occures in your app.

   The bad news is that if this BER encoding bug also affects Integer values, 
   in that case it is theoretically impossible to fix because, unlike Counter,
   Integer values may legally be negative so they could not unconditionally be 
   converted into positives.

   Therefore the best solutoin would be to get vendors fixing their 
   BER encoders.

