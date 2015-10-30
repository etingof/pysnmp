  
Garbaged SNMP values (tools)
----------------------------

Q. When fetching data with snmp*.py command-line tools, some values 
   do not print out nicely:

.. code-block:: bash

    $ snmpget.py -v2c -c public 127.0.0.1 .1.3.6.1.4.1.14988.1.1.1.2.1.1.0.23.183.34.8.200.3
    SNMPv2-SMI::enterprises.14988.1.1.1.2.1.1.0.23.183.34.8.200.3 = 
    OctetString: Ë‡ÄŒ

   where Net-SNMP gives nicely formatted human-readable string:

.. code-block:: bash

    $ snmpget -v2c -c public 127.0.0.1 .1.3.6.1.4.1.14988.1.1.1.2.1.1.0.23.183.34.8.200.3
    SNMPv2-SMI::enterprises.14988.1.1.1.2.1.1.0.23.183.34.8.200.3 = 
    Hex-STRING: 00 17 B7 22 08 C8

   What can be done to PySNMP to make it returning HEX data in human-readable?

A. The difference is that Net-SNMP prints values into hex by-default, 
   whereas pysnmp does not do that. You can force snmpget.py to work
   similarily with the -OT command line parameter.

.. code-block:: bash

    $ snmpget.py -OT -v2c -c public 127.0.0.1 .1.3.6.1.4.1.14988.1.1.1.2.1.1.0.23.
    183.34.8.200.3
    SNMPv2-SMI::enterprises.14988.1.1.1.2.1.1.0.23.183.34.8.200.3 = 
    OctetString: 00 17 b7 22 08 c8

Another matter is MIB lookup - when snmp*.py tool can use a MIB to figure 
out what are the display conventions for particular value type, it will 
reformat the value in a human-readable form.

To let MIB lookup work, please pass appropriate MIB name to snmp*.py
tool through command line:

.. code-block:: bash

    $ snmpwalk.py -m IP-MIB,IF-MIB -v2c -c public 127.0.0.1 .1.3.6.1.4.1
