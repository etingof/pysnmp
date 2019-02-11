"""
Walk multiple Agents at once
++++++++++++++++++++++++++++

Iterate over MIBs of multiple SNMP Agents asynchronously using the
following options:

* with SNMPv1, community 'public' and 
  with SNMPv2c, community 'public' and
* over IPv4/UDP and 
  over IPv6/UDP
* to an Agent at demo.snmplabs.com:161 and
  to an Agent at [::1]:161
* pull MIB variables till EOM
* Enable MIB lookup feature

"""#
from pysnmp.hlapi.v1arch.asyncore import *

# List of targets in the following format:
# ((authData, transportTarget, varNames), ...)
TARGETS = (
    # 1-st target (SNMPv1 over IPv4/UDP)
    (CommunityData('public', mpModel=0),
     UdpTransportTarget(('demo.snmplabs.com', 161)),
     (ObjectType(ObjectIdentity('1.3.6.1.2.1')),
      ObjectType(ObjectIdentity('1.3.6.1.3.1')))),

    # 2-nd target (SNMPv2c over IPv4/UDP)
    (CommunityData('public'),
     UdpTransportTarget(('demo.snmplabs.com', 161)),
     (ObjectType(ObjectIdentity('1.3.6.1.4.1')),)),

    # 3-th target (SNMPv3 over IPv6/UDP)
    (CommunityData('public'),
     Udp6TransportTarget(('::1', 161)),
     (ObjectType(ObjectIdentity('IF-MIB', 'ifTable')),))

    # N-th target
    # ...
)


def cbFun(errorIndication, errorStatus, errorIndex, varBindTable, **context):
    if errorIndication:
        print(errorIndication)

    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))

    else:
        for varBindRow in varBindTable:
            for varBind in varBindRow:
                print(' = '.join([x.prettyPrint() for x in varBind]))

        return context.get('nextVarBinds')


snmpDispatcher = SnmpDispatcher()

# Submit a bunch of initial GETNEXT requests
for authData, transportTarget, varBinds in TARGETS:
    nextCmd(snmpDispatcher, authData, transportTarget, *varBinds,
            cbFun=cbFun, lookupMib=True)

snmpDispatcher.transportDispatcher.runDispatcher()
