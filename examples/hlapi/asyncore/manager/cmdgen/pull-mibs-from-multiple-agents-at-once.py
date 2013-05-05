##
# Asynchronous Command Generator
#
# Send a bunch of SNMP GETNEXT requests all at once using the following options:
#
# * with SNMPv1, community 'public' and 
#   with SNMPv2c, community 'public' and
#   with SNMPv3, user 'usr-md5-des', MD5 auth and DES privacy
# * over IPv4/UDP and 
#   over IPv6/UDP
# * to an Agent at demo.snmplabs.com:161 and
#   to an Agent at [::1]:161
# * for multiple MIB subtrees and tables
#
from pysnmp.entity.rfc3413.oneliner import cmdgen

# List of targets in the followin format:
# ( ( authData, transportTarget, varNames ), ... )
targets = (
    # 1-st target (SNMPv1 over IPv4/UDP)
    ( cmdgen.CommunityData('public', mpModel=0),
      cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161)),
      ( '1.3.6.1.2.1', '1.3.6.1.3.1') ),
    # 2-nd target (SNMPv2c over IPv4/UDP)
    ( cmdgen.CommunityData('public'),
      cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161)),
      ( '1.3.6.1.4.1', ) ),
    # 3-nd target (SNMPv3 over IPv4/UDP)
    ( cmdgen.UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
      cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161)),
      ( cmdgen.MibVariable('SNMPv2-MIB', 'system'), ) ),
    # 4-th target (SNMPv3 over IPv6/UDP)
    ( cmdgen.UsmUserData('usr-md5-none', 'authkey1'),
      cmdgen.Udp6TransportTarget(('::1', 161)),
      ( cmdgen.MibVariable('IF-MIB', 'ifTable'), ) )
    # N-th target
    # ...
)

# Wait for responses or errors, submit GETNEXT requests for further OIDs
def cbFun(sendRequestHandle, errorIndication, errorStatus, errorIndex,
          varBindTable, cbCtx):
    (varBindHead, authData, transportTarget) = cbCtx
    print('%s via %s' % (authData, transportTarget))
    if errorIndication:
        print(errorIndication)
        return
    if errorStatus:
        print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBindTable[-1][int(errorIndex)-1][0] or '?'
            )
        )
        return
    varBindTableRow = varBindTable[-1]
    for idx in range(len(varBindTableRow)):
        name, val = varBindTableRow[idx]
        if val is not None and varBindHead[idx] <= name:
            # still in table
            break
    else:
        print('went out of table at %s' % (name, ))
        return

    for varBindRow in varBindTable:
        for oid, val in varBindRow:
            if val is None:
                print(oid.prettyPrint())
            else:
                print('%s = %s' % (oid.prettyPrint(), val.prettyPrint()))

    return True # continue table retrieval

cmdGen  = cmdgen.AsynCommandGenerator()

# Submit initial GETNEXT requests and wait for responses
for authData, transportTarget, varNames in targets:
    varBindHead = [ x[0] for x in cmdGen.makeReadVarBinds(varNames) ]
    cmdGen.nextCmd(
        authData, transportTarget, varNames,
        # User-space callback function and its context
        (cbFun, (varBindHead, authData, transportTarget)),
        lookupNames=True, lookupValues=True
    )

cmdGen.snmpEngine.transportDispatcher.runDispatcher()
