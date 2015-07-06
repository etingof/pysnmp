#
# Command Generator
#
# Send SNMP SET request using the following options:
#
# * with SNMPv1, community 'public'
# * over IPv4/UDP
# * to an Agent at demo.snmplabs.com:161
# * setting two OIDs to new values (types explicitly specified)
#
from pysnmp.entity.rfc3413.oneliner.cmdgen import *
from pysnmp.proto import rfc1902

for errorIndication, \
    errorStatus, errorIndex, \
    varBinds in setCmd(SnmpEngine(),
                       CommunityData('public', mpModel=0),
                       UdpTransportTarget(('demo.snmplabs.com', 161)),
                       ContextData(),
                       ('1.3.6.1.2.1.1.9.1.2.1', rfc1902.ObjectName('1.3.6.1.4.1.20408.1.1')),
                       ('1.3.6.1.2.1.1.9.1.2.1', '1.3.6.1.4.1.20408.1.1'),
                       ('1.3.6.1.2.1.1.9.1.3.1', rfc1902.OctetString('new system name'))):
    # Check for errors and print out results
    if errorIndication:
        print(errorIndication)
    else:
        if errorStatus:
            print('%s at %s' % (
                    errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex)-1][0] or '?'
                )
            )
        else:
            for varBind in varBinds:
                print(' = '.join([ x.prettyPrint() for x in varBind ]))
    break
