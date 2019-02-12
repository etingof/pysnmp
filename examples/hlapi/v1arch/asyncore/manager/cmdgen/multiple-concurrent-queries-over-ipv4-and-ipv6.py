"""
Multiple concurrent queries
+++++++++++++++++++++++++++

Send a bunch of different SNMP GET requests to different peers all at once,
wait for responses asynchronously:

* with SNMPv1, community 'public' and 
  with SNMPv2c, community 'public' and
* over IPv4/UDP and 
  over IPv6/UDP
* to an Agent at demo.snmplabs.com:161 and
  to an Agent at [::1]:161
* for instances of SNMPv2-MIB::system
  SNMPv2-MIB::sysLocation.0 MIB objects
* Enable MIB lookup feature
"""#
from pysnmp.hlapi.v1arch.asyncore import *

# List of targets in the following format:
# ((authData, transportTarget, varNames), ...)
TARGETS = (
    # 1-st target (SNMPv1 over IPv4/UDP)
    (CommunityData('public', mpModel=0),
     UdpTransportTarget(('demo.snmplabs.com', 161)),
     (ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
      ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysLocation', 0)))),

    # 2-nd target (SNMPv2c over IPv4/UDP)
    (CommunityData('public'),
     UdpTransportTarget(('demo.snmplabs.com', 161)),
     (ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
      ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysLocation', 0)))),

    # 3-nd target (SNMPv2c over IPv4/UDP) - same community and
    # different transport address.
    (CommunityData('public'),
     Udp6TransportTarget(('::1', 161)),
     (ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysContact', 0)),
      ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)))),

    # N-th target
    # ...
)


def cbFun(errorIndication, errorStatus, errorIndex, varBinds, **context):
    if errorIndication:
        print(errorIndication)

    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))

    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))


snmpDispatcher = SnmpDispatcher()

# Submit a bunch of initial GET requests
for authData, transportTarget, varBinds in TARGETS:
    getCmd(snmpDispatcher, authData, transportTarget, *varBinds,
           cbFun=cbFun, lookupMib=True)

snmpDispatcher.transportDispatcher.runDispatcher()
