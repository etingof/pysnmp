#
# Command Generator
#
# Send SNMP GET request using the following options:
#
# * with SNMPv1, community 'public'
# * over IPv4/UDP
# * to an Agent at demo.snmplabs.com:161
# * for two instances of SNMPv2-MIB::sysDescr.0 MIB object,
# * one in label and another in MIB symbol form
#
from pysnmp.entity.rfc3413.oneliner import cmdgen

cmdGen = cmdgen.CommandGenerator()

errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
    cmdgen.CommunityData('public', mpModel=0),
    cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161)),
    cmdgen.MibVariable('iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0'),
    cmdgen.MibVariable('SNMPv2-MIB', 'sysDescr', 0)
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

