"""
Multiple concurrent queries
+++++++++++++++++++++++++++

Send a bunch of different SNMP GET requests to different peers all at once,
wait for responses asynchronously:

* with SNMPv1, community 'public' and 
  with SNMPv2c, community 'public' and
  with SNMPv3, user 'usr-md5-des', MD5 auth and DES privacy
* over IPv4/UDP and 
  over IPv6/UDP
* to an Agent at demo.snmplabs.com:161 and
  to an Agent at [::1]:161
* for instances of SNMPv2-MIB::sysDescr.0 and
  SNMPv2-MIB::sysLocation.0 MIB objects

"""#
from pysnmp.hlapi.asyncore import *

# List of targets in the followin format:
# ( ( authData, transportTarget, varNames ), ... )
targets = (
    # 1-st target (SNMPv1 over IPv4/UDP)
    ( CommunityData('public', mpModel=0),
      UdpTransportTarget(('demo.snmplabs.com', 161)),
      ( ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysLocation', 0) )) ),
    # 2-nd target (SNMPv2c over IPv4/UDP)
    ( CommunityData('public'),
      UdpTransportTarget(('demo.snmplabs.com', 161)),
      ( ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysLocation', 0) )) ),
    # 3-nd target (SNMPv2c over IPv4/UDP) - same community and 
    # different transport address.
    ( CommunityData('public'),
      UdpTransportTarget(('localhost', 161)),
      ( ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysContact', 0)),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0))) ),
    # 4-nd target (SNMPv3 over IPv4/UDP)
    ( UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
      UdpTransportTarget(('demo.snmplabs.com', 161)),
      ( ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysLocation', 0) )) ),
    # 5-th target (SNMPv3 over IPv6/UDP)
    ( UsmUserData('usr-md5-none', 'authkey1'),
      Udp6TransportTarget(('::1', 161)),
      ( ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysLocation', 0) )) ),
    # N-th target
    # ...
)

# Wait for responses or errors
def cbFun(snmpEngine, sendRequestHandle, errorIndication, 
          errorStatus, errorIndex, varBinds, cbCtx):
    authData, transportTarget = cbCtx
    print('%s via %s' % (authData, transportTarget))
    if errorIndication:
        print(errorIndication)
        return True
    elif errorStatus:
        print('%s at %s' % (
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex)-1][0] or '?'
            )
        )
        return True
    else:    
        for varBind in varBinds:
            print(' = '.join([ x.prettyPrint() for x in varBind ]))

snmpEngine = SnmpEngine()

# Submit GET requests
for authData, transportTarget, varNames in targets:
    getCmd(snmpEngine, authData, transportTarget, ContextData(), *varNames,
           **dict(cbFun=cbFun, cbCtx=(authData, transportTarget)))

snmpEngine.transportDispatcher.runDispatcher()
