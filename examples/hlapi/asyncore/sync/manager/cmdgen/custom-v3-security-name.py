#
# Command Generator
#
# Send SNMP GET request using the following options:
#
# * with SNMPv3, user 'usr-md5-none', securityName 'myuser'
#   MD5 authentication, no privacy
# * over IPv4/UDP
# * to an Agent at demo.snmplabs.com:161
# * for an OID in text form
#
# The securityName parameter can be thought as an alias to userName and
# allows you to address a USM Table row just as userName does. However
# securityName can be made human-readable, also it is not an index in
# usmUserTable, thus duplicate securityName parameters are possible.
#
from pysnmp.entity.rfc3413.oneliner import cmdgen

cmdGen = cmdgen.CommandGenerator()

errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
    cmdgen.UsmUserData('usr-md5-none', 'authkey1', securityName='myuser'),
    cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161)),
    '1.3.6.1.2.1.1.1.0'
)

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
        for name, val in varBinds:
            print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
