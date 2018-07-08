"""
SNMPv2c TRAP via NOTIFICATION-TYPE
++++++++++++++++++++++++++++++++++

Initialize TRAP message contents from variables specified
in *NOTIFICATION-TYPE* SMI macro.

* SNMPv2c
* with community name 'public'
* over IPv4/UDP
* send TRAP notification
* with TRAP ID 'linkUp' specified as a MIB symbol
* include values for managed objects implicitly added to notification
  (via NOTIFICATION-TYPE->OBJECTS)

Functionally similar to:

| $ snmptrap -v2c -c public demo.snmplabs.com 0 1.3.6.1.6.3.1.1.5.1 1.3.6.1.2.1.2.2.1.1.123 i 123 1.3.6.1.2.1.2.2.1.7.123 i 1 1.3.6.1.2.1.2.2.1.8.123 i 1

"""#
from pysnmp.hlapi import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    sendNotification(
        SnmpEngine(),
        CommunityData('public'),
        UdpTransportTarget(('demo.snmplabs.com', 162)),
        ContextData(),
        'trap',
        NotificationType(
            ObjectIdentity('IF-MIB', 'linkUp'),
                           instanceIndex=(123,),
                           objects={('IF-MIB', 'ifIndex'): 123,
                                    ('IF-MIB', 'ifAdminStatus'): 'up',
                                    ('IF-MIB', 'ifOperStatus'): 'up'}
        )
    )
)

if errorIndication:
    print(errorIndication)
