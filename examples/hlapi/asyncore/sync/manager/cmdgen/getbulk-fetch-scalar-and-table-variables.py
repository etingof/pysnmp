#
# Command Generator
#
# Send SNMP GETBULK request using the following options:
#
# * with SNMPv3 with user 'usr-md5-des', MD5 auth and DES privacy protocols
# * over IPv6/UDP
# * to an Agent at [::1]:161
# * with values non-repeaters = 1, max-repetitions = 25
# * for IP-MIB::ipAdEntAddr and all columns of the IF-MIB::ifEntry table
# * stop when response OIDs leave the scopes of the table OR maxRows == 20
# * perform response OIDs and values resolution at MIB
#
from pysnmp.entity.rfc3413.oneliner import cmdgen

cmdGen = cmdgen.CommandGenerator()

# Send a series of SNMP GETBULK requests
# make sure IF-MIB.py and IP-MIB.py are in search path

errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.bulkCmd(
    cmdgen.UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
    cmdgen.Udp6TransportTarget(('::1', 161)),
    1, 25,
    cmdgen.MibVariable('IP-MIB', 'ipAdEntAddr'),
    cmdgen.MibVariable('IF-MIB', 'ifEntry'),
    lookupNames=True, lookupValues=True, maxRows=20
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
