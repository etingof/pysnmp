#
# Command Generator
#
# Send SNMP GETNEXT requests using the following options:
#
# * with SNMPv3, user 'usr-sha-aes128', SHA auth, AES128 privacy
# * over Local Domain Sockets
# * to an Agent at demo.snmplabs.com:161
# * for all OIDs past IF-MIB (load up all MIBs in search path)
# * run till end-of-mib condition is reported by Agent OR maxRows == 100
# * ignoring non-increasing OIDs whenever reported by Agent
#
# make sure IF-MIB.py is search path
#
from pysnmp.entity.rfc3413.oneliner.cmdgen import *

for errorIndication, \
    errorStatus, errorIndex, \
    varBinds in nextCmd(SnmpEngine(),
                        UsmUserData('usr-sha-aes128', 'authkey1', 'privkey1',
                                    authProtocol=usmHMACSHAAuthProtocol,
                                    privProtocol=usmAesCfb128Protocol),
                        UdpTransportTarget(('demo.snmplabs.com', 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('IF-MIB', '').loadMibs()),
                        lexicographicMode=True, maxRows=100,
                        ignoreNonIncreasingOid=True):
    # Check for errors and print out results
    if errorIndication:
        print(errorIndication)
        break
    else:
        if errorStatus:
            print('%s at %s' % (
                    errorStatus.prettyPrint(),
                    errorIndex and varBinds[int(errorIndex)-1][0] or '?'
                )
            )
            break
        else:
            for varBind in varBinds:
                print(' = '.join([ x.prettyPrint() for x in varBind ]))
