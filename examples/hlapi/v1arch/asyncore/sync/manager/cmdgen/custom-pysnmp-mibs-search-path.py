"""
Custom PySNMP MIBs location
+++++++++++++++++++++++++++

Send a series of SNMP GETBULK requests using the following options:

* with SNMPv2c, community 'public'
* over IPv4/UDP
* to an Agent at demo.snmplabs.com:161
* for all OIDs within TCP-MIB::tcpConnTable column
* TCP-MIB Python module will be searched by a user-specified filesystem
  path (/opt/mib/pysnmp) and in Python package (python_packaged_mibs)
  which should be in sys.path
* with MIB lookup enabled

Functionally similar to:

| $ snmpbulkwalk -v2c -c public -Cn0 -Cr50 demo.snmplabs.com TCP-MIB::tcpConnTable

"""#
from pysnmp.hlapi.v1arch import *

for (errorIndication,
     errorStatus,
     errorIndex,
     varBinds) in bulkCmd(SnmpDispatcher(),
                          CommunityData('public'),
                          UdpTransportTarget(('demo.snmplabs.com', 161)),
                          0, 50,
                          ObjectType(
                              ObjectIdentity('TCP-MIB', 'tcpConnTable').addMibSource(
                                  '/opt/mibs/pysnmp').addMibSource(
                                  'python_packaged_mibs')
                          ),
                          lookupMib=True,
                          lexicographicMode=False):

    if errorIndication:
        print(errorIndication)
        break

    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        break

    else:
        for varBind in varBinds:
            print(' = '.join([x.prettyPrint() for x in varBind]))
