
Resolve response values at MIB
------------------------------

Q. My CommandGenerator app reports OIDs and values in form of PyASN1 
   objects. How do I convert them into human-readable, symbolic names 
   and values?

A. The most easy to use interface to MIB lookup feature is supported by 
   PySNMP 4.2.3 and later. Just pass the

.. code-block:: python

    lookupNames=True, lookupValues=True

parameters to getCmd(), setCmd(), nextCmd(), bulkCmd() methods of 
oneliner CommandGenerator. Then the OIDs in response variable-binding 
list will get replaced by similarily looking MibVariable instances, 
their prettyPrint() methods return MIB symbols instead of OIDs.

Response values will still be PyASN1 objects but some may be replaced 
by TEXTUAL-CONVENTION decorators what make their prettyPrint() methods 
returning even more human-friendly output.

.. code-block:: python

    >>> from pysnmp.entity.rfc3413.oneliner import cmdgen
    >>> 
    >>> cmdGen = cmdgen.CommandGenerator()
    >>> 
    >>> errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
    ...     cmdgen.CommunityData('public'),
    ...     cmdgen.UdpTransportTarget(('localhost', 161)),
    ...     '1.3.6.1.2.1.1.1.0',
    ...     lookupNames=True, lookupValues=True
    ... )
    >>>
    >>> name, value = varBinds[0]
    >>> name
    MibVariable(ObjectName(1.3.6.1.2.1.1.1.0))
    >>> value
    DisplayString('Linux saturn 2.6.38.1 Sat Apr 9 23:39:07 CDT 2012 i686')
    >>> name.prettyPrint()
    'SNMPv2-MIB::sysDescr."0"'
    >>> value.prettyPrint()
    'Linux cray 2.6.37.6-smp #2 SMP Sat Apr 9 23:39:07 CDT 2011 i686'
    >>>

If you are using older PySNMP versions it's strongly recommended to 
upgrade to the latest one.
