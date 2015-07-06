#
# Command Generator
#
# Send SNMP GETBULK request using the following options:
#
# * with SNMPv3, user 'usr-none-none', no authentication, no privacy
# * over IPv4/UDP
# * to an Agent at demo.snmplabs.com:161
# * for all OIDs past TCP-MIB::tcpConnTable
# * TCP-MIB will be searched by a user-specified path
# * run till end-of-mib condition is reported by Agent OR maxRows == 100 OR
#   maxCalls == 10 request-response interactions occur
# * ignoring non-increasing OIDs whenever reported by Agent
#
from pysnmp.entity.rfc3413.oneliner.cmdgen import *

for errorIndication, \
    errorStatus, errorIndex, \
    varBinds in bulkCmd(SnmpEngine(),
                        UsmUserData('usr-none-none'),
                        UdpTransportTarget(('demo.snmplabs.com', 161)),
                        ContextData(),
                        0, 50,
                        ObjectType(ObjectIdentity('TCP-MIB', 'tcpConnTable').addMibSource('/tmp/mibs')),
                        maxRows=100, maxCalls=10,
                        lexicographicMode=True, 
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
