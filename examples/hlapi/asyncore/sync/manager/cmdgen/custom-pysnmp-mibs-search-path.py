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
# * run till end-of-mib condition is reported by Agent OR maxRows == 20
# * ignoring non-increasing OIDs whenever reported by Agent
#
# make sure IF-MIB.py is search path
#
from pysnmp.entity.rfc3413.oneliner import cmdgen

cmdGen = cmdgen.CommandGenerator()

errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.bulkCmd(
    cmdgen.UsmUserData('usr-none-none'),
    cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161)),
    0, 50,
    cmdgen.MibVariable('TCP-MIB', 'tcpConnTable').addMibSource('/tmp/mymibs'),
    lexicographicMode=True, maxRows=100, ignoreNonIncreasingOid=True
)

if errorIndication:
    print(errorIndication)
else:
    if errorStatus:
        print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBindTable[-1][int(errorIndex)-1][0] or '?'
            )
        )
    else:
        for varBindTableRow in varBindTable:
            for name, val in varBindTableRow:
                print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
