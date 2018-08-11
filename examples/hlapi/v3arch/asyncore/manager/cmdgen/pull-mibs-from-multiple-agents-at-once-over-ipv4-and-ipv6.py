"""
Walk multiple Agents at once
++++++++++++++++++++++++++++

Iterate over MIBs of multiple SNMP Agents asynchronously using the
following options:

* with SNMPv1, community 'public' and 
  with SNMPv2c, community 'public' and
  with SNMPv3, user 'usr-md5-des', MD5 auth and DES privacy
* over IPv4/UDP and 
  over IPv6/UDP
* to an Agent at demo.snmplabs.com:161 and
  to an Agent at [::1]:161
* pull variables till EOM

"""#
from pysnmp.hlapi.v3arch.asyncore import *

# List of targets in the following format:
# ((authData, transportTarget, varNames), ...)
targets = (
    # 1-st target (SNMPv1 over IPv4/UDP)
    (CommunityData('public', mpModel=0),
     UdpTransportTarget(('demo.snmplabs.com', 161)),
     (ObjectType(ObjectIdentity('1.3.6.1.2.1')),
      ObjectType(ObjectIdentity('1.3.6.1.3.1')))),
    # 2-nd target (SNMPv2c over IPv4/UDP)
    (CommunityData('public'),
     UdpTransportTarget(('demo.snmplabs.com', 161)),
     (ObjectType(ObjectIdentity('1.3.6.1.4.1')),)),
    # 3-nd target (SNMPv3 over IPv4/UDP)
    (UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
     UdpTransportTarget(('demo.snmplabs.com', 161)),
     (ObjectType(ObjectIdentity('SNMPv2-MIB', 'system')),)),
    # 4-th target (SNMPv3 over IPv6/UDP)
    (UsmUserData('usr-md5-none', 'authkey1'),
     Udp6TransportTarget(('::1', 161)),
     (ObjectType(ObjectIdentity('IF-MIB', 'ifTable')),))
    # N-th target
    # ...
)


# Wait for responses or errors, submit GETNEXT requests for further OIDs
# noinspection PyUnusedLocal,PyUnusedLocal
def cbFun(snmpEngine, sendRequestHandle, errorIndication,
          errorStatus, errorIndex, varBindTable, cbCtx):
    (authData, transportTarget) = cbCtx
    print('%s via %s' % (authData, transportTarget))
    if errorIndication:
        print(errorIndication)
        return
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBindTable[-1][int(errorIndex) - 1][0] or '?'))
        return
    else:
        for varBindRow in varBindTable:
            for varBind in varBindRow:
                print(' = '.join([x.prettyPrint() for x in varBind]))

        return True  # continue table retrieval


snmpEngine = SnmpEngine()

# Submit initial GETNEXT requests and wait for responses
for authData, transportTarget, varBinds in targets:
    nextCmd(snmpEngine, authData, transportTarget, ContextData(),
            *varBinds, **dict(cbFun=cbFun, cbCtx=(authData, transportTarget)))

snmpEngine.transportDispatcher.runDispatcher()
