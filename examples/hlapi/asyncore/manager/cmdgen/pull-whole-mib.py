"""
Walk whole MIB
++++++++++++++

Send a series of SNMP GETNEXT requests using the following options:

* with SNMPv3, user 'usr-md5-none', MD5 authentication, no privacy
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for all OIDs in IF-MIB

Functionally similar to:

| $ snmpwalk -v3 -lauthNoPriv -u usr-md5-none -A authkey1 -X privkey1 \
|            demo.snmplabs.com  IF-MIB::

"""#
from pysnmp.hlapi.asyncore import *

def cbFun(snmpEngine, sendRequestHandle, errorIndication, 
          errorStatus, errorIndex, varBindTable, cbCtx):
    if errorIndication:
        print(errorIndication)
        return
    elif errorStatus:
        print('%s at %s' % (
                errorStatus.prettyPrint(),
                errorIndex and varBindTable[-1][int(errorIndex)-1][0] or '?'
            )
        )
        return
    else:
        for varBindRow in varBindTable:
            for varBind in varBindRow:
                print(' = '.join([ x.prettyPrint() for x in varBind ]))

    return True  # request lower layers to do GETNEXT and call us back

snmpEngine = SnmpEngine()

nextCmd(snmpEngine,
         UsmUserData('usr-md5-none', 'authkey1'),
         UdpTransportTarget(('demo.snmplabs.com', 161)),
         ContextData(),
         ObjectType(ObjectIdentity('SNMPv2-MIB', 'system')),
         ObjectType(ObjectIdentity('IF-MIB', 'ifTable')),
         cbFun=cbFun)

snmpEngine.transportDispatcher.runDispatcher()
