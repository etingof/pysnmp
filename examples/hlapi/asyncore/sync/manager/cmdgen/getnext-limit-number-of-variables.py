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
from pysnmp.entity.rfc3413.oneliner import cmdgen

cmdGen = cmdgen.CommandGenerator()

errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.nextCmd(
    cmdgen.UsmUserData('usr-sha-aes128', 'authkey1', 'privkey1',
                       authProtocol=cmdgen.usmHMACSHAAuthProtocol,
                       privProtocol=cmdgen.usmAesCfb128Protocol),
    cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161)),
    cmdgen.MibVariable('IF-MIB', '').loadMibs(),
    lexicographicMode=True, maxRows=100,
    ignoreNonIncreasingOid=True
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
