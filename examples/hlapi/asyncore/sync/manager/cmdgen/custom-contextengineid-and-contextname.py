#
# Command Generator
#
# Send SNMP SET request using the following options:
#
# * with SNMPv3 with user 'usr-md5-none', MD5 auth and no privacy protocols
# * over IPv4/UDP
# * to an Agent at demo.snmplabs.com:161
# * addressing particular set of Managed Objects at remote SNMP Engine by:
#   * contextEngineId 0x80004fb805636c6f75644dab22cc and
#   * contextName 'a172334d7d97871b72241397f713fa12'
# * setting SNMPv2-MIB::sysName.0 to new value (type taken from MIB)
#
from pysnmp.entity.rfc3413.oneliner.cmdgen import *
from pysnmp.proto import rfc1902

for errorIndication, \
    errorStatus, errorIndex, \
    varBinds in setCmd(SnmpEngine(),
                       UsmUserData('usr-md5-none', 'authkey1'),
                       UdpTransportTarget(('demo.snmplabs.com', 161)),
                       ContextData(
                           contextEngineId=rfc1902.OctetString(hexValue='80004fb805636c6f75644dab22cc'),
                           contextName='da761cfc8c94d3aceef4f60f049105ba'
                       ),
                       ObjectType(
                           ObjectIdentity('SNMPv2-MIB', 'sysORDescr', 1),
                           'new system name'
                       )):
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
