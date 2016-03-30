"""
SNMPv2c
+++++++

Send SNMP GET request using the following options:

  * with SNMPv1, community 'public'
  * over IPv4/UDP
  * to an Agent at demo.snmplabs.com:161
  * for two instances of SNMPv2-MIB::sysDescr.0 MIB object,

Functionally similar to:

| $ snmpget -v2c -c public demo.snmplabs.com SNMPv2-MIB::sysDescr.0

"""#
from pysnmp.hlapi.asyncore import *


# noinspection PyUnusedLocal,PyUnusedLocal,PyUnusedLocal
def cbFun(snmpEngine, sendRequestHandle, errorIndication,
          errorStatus, errorIndex, varBinds, cbCtx):
    if errorIndication:
        print(errorIndication)
        return
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBindTable[-1][int(errorIndex) - 1][0] or '?'))
        return
    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))


snmpEngine = SnmpEngine()

getCmd(snmpEngine,
       CommunityData('public'),
       UdpTransportTarget(('demo.snmplabs.com', 161)),
       ContextData(),
       ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
       cbFun=cbFun)

snmpEngine.transportDispatcher.runDispatcher()
