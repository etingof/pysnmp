#
# Command Generator
#
# Send SNMP GET request using the following options:
#
# * with SNMPv3, user 'usr-sha-aes128', SHA auth, AES128 privacy
# * over IPv4/UDP
# * to an Agent at demo.snmplabs.com:161
# * for TCP-MIB::tcpConnLocalAddress."0.0.0.0".22."0.0.0.0".0 MIB object
#
from pysnmp.entity.rfc3413.oneliner.cmdgen import *

for errorIndication, \
    errorStatus, errorIndex, \
    varBinds in getCmd(SnmpEngine(),
                       UsmUserData('usr-sha-aes128', 'authkey1', 'privkey1',
                                   authProtocol=usmHMACSHAAuthProtocol,
                                   privProtocol=usmAesCfb128Protocol ),
                       UdpTransportTarget(('demo.snmplabs.com', 161)),
                       ContextData(),
                       ObjectType(
                           ObjectIdentity('TCP-MIB',
                                          'tcpConnLocalAddress',
                                          '0.0.0.0', 22,
                                          '0.0.0.0', 0)
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
