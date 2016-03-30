"""
Custom SNMPv1 TRAP
++++++++++++++++++

Send SNMPv1 TRAP through unified SNMPv3 message processing framework.

Original v1 TRAP fields are mapped into dedicated variable-bindings,
(see `RFC2576 <https://www.ietf.org/rfc/rfc2576.txt>`_) for details.

* SNMPv1
* with community name 'public'
* over IPv4/UDP
* send TRAP notification
* with Generic Trap #6 (enterpriseSpecific) and Specific Trap 432
* overriding Uptime value with 12345
* overriding Agent Address with '127.0.0.1'
* overriding Enterprise OID with 1.3.6.1.4.1.20408.4.1.1.2
* include managed object information '1.3.6.1.2.1.1.1.0' = 'my system'

Functionally similar to:

| $ snmptrap -v1 -c public demo.snmplabs.com 1.3.6.1.4.1.20408.4.1.1.2 127.0.0.1 6 432 12345 1.3.6.1.2.1.1.1.0 s "my system"

"""#
from pysnmp.hlapi import *

errorIndication, errorStatus, errorIndex, varBinds = next(
    sendNotification(
        SnmpEngine(),
        CommunityData('public', mpModel=0),
        UdpTransportTarget(('demo.snmplabs.com', 162)),
        ContextData(),
        'trap',
        NotificationType(
            ObjectIdentity('1.3.6.1.4.1.20408.4.1.1.2.0.432'),
        ).addVarBinds(
            ('1.3.6.1.2.1.1.3.0', 12345),
            ('1.3.6.1.6.3.18.1.3.0', '127.0.0.1'),
            ('1.3.6.1.6.3.1.1.4.3.0', '1.3.6.1.4.1.20408.4.1.1.2'),
            ('1.3.6.1.2.1.1.1.0', OctetString('my system'))
        )
    )
)
if errorIndication:
    print(errorIndication)
