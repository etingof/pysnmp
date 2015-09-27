"""
SNMPv2c TRAP via NOTIFICATION-TYPE
++++++++++++++++++++++++++++++++++

Initialize TRAP message contents from variables specified
in *NOTIFICATION-TYPE* SMI macro.

* SNMPv2c
* with community name 'public'
* over IPv4/UDP
* send TRAP notification
* with TRAP ID 'coldStart' specified as a MIB symbol
* include managed object information specified as a MIB symbol

Functionally similar to:

| $ snmptrap -v2c -c public demo.snmplabs.com \
|   12345
|   1.3.6.1.4.1.20408.4.1.1.2

"""#
from pysnmp.hlapi import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    sendNotification(SnmpEngine(),
                     CommunityData('public'),
                     UdpTransportTarget(('localhost', 162)),
                     ContextData(),
                     'trap',
                     NotificationType(
                         ObjectIdentity('SNMPv2-MIB', 'coldStart')
                     )
    )
)

if errorIndication:
    print(errorIndication)
