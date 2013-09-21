#
# Multithreaded, synchronous Command Generator
#
# Send a bunch of SNMP GET requests simultaneously using the following options:
#
# * process 5 GET requests in 3 parallel threads
# * with SNMPv1, community 'public' and 
#   with SNMPv2c, community 'public' and
#   with SNMPv3, user 'usr-md5-des', MD5 auth and DES privacy
# * over IPv4/UDP and 
#   over IPv6/UDP
# * to an Agent at demo.snmplabs.com:161 and
#   to an Agent at [::1]:161
# * for instances of SNMPv2-MIB::sysDescr.0 and
#   SNMPv2-MIB::sysLocation.0 MIB objects
#
from sys import version_info
if version_info[0] == 2:
    from Queue import Queue
else:
    from queue import Queue
from threading import Thread
from pysnmp.entity.rfc3413.oneliner import cmdgen

# List of targets in the followin format:
# ( ( authData, transportTarget, varNames ), ... )
targets = (
    # 1-st target (SNMPv1 over IPv4/UDP)
    ( cmdgen.CommunityData('public', mpModel=0),
      cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161)),
      ( cmdgen.MibVariable('SNMPv2-MIB', 'sysDescr', 0),
        cmdgen.MibVariable('SNMPv2-MIB', 'sysLocation', 0) ) ),
    # 2-nd target (SNMPv2c over IPv4/UDP)
    ( cmdgen.CommunityData('public'),
      cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161)),
      ( cmdgen.MibVariable('SNMPv2-MIB', 'sysDescr', 0),
        cmdgen.MibVariable('SNMPv2-MIB', 'sysLocation', 0) ) ),
    # 3-nd target (SNMPv2c over IPv4/UDP) - same community and 
    # different transport address.
    ( cmdgen.CommunityData('public'),
      cmdgen.UdpTransportTarget(('localhost', 161)),
      ( cmdgen.MibVariable('SNMPv2-MIB', 'sysContact', 0),
        cmdgen.MibVariable('SNMPv2-MIB', 'sysName', 0) ) ),
    # 4-nd target (SNMPv3 over IPv4/UDP)
    ( cmdgen.UsmUserData('usr-md5-des', 'authkey1', 'privkey1'),
      cmdgen.UdpTransportTarget(('demo.snmplabs.com', 161)),
      ( cmdgen.MibVariable('SNMPv2-MIB', 'sysDescr', 0),
        cmdgen.MibVariable('SNMPv2-MIB', 'sysLocation', 0) ) ),
    # 5-th target (SNMPv3 over IPv6/UDP)
    ( cmdgen.UsmUserData('usr-md5-none', 'authkey1'),
      cmdgen.Udp6TransportTarget(('::1', 161)),
      ( cmdgen.MibVariable('SNMPv2-MIB', 'sysDescr', 0),
        cmdgen.MibVariable('SNMPv2-MIB', 'sysLocation', 0) ) ),
    # N-th target
    # ...
)

class Worker(Thread):
    def __init__(self, requests, responses):
        Thread.__init__(self)
        self.requests = requests
        self.responses = responses
        self.cmdGen = cmdgen.CommandGenerator()
        self.setDaemon(True)
        self.start()
    
    def run(self):
        while True:
            authData, transportTarget, varNames = self.requests.get()
            self.responses.append(
                self.cmdGen.getCmd(
                    authData, transportTarget, *varNames,
                    **{ 'lookupNames': True, 'lookupValues': True }
                )
            )
            if hasattr(self.requests, 'task_done'):  # 2.5+
                self.requests.task_done()

class ThreadPool:
    def __init__(self, num_threads):
        self.requests = Queue(num_threads)
        self.responses = []
        for _ in range(num_threads):
            Worker(self.requests, self.responses)

    def addRequest(self, authData, transportTarget, varBinds):
        self.requests.put((authData, transportTarget, varBinds))

    def getResponses(self): return self.responses

    def waitCompletion(self):
        if hasattr(self.requests, 'join'):
            self.requests.join()  # 2.5+
        else:
            from time import sleep
            # this is a lame substitute for missing .join()
            # adding an explicit synchronization might be a better solution
            while not self.requests.empty():  
                sleep(1) 

pool = ThreadPool(3)

# Submit GET requests
for authData, transportTarget, varNames in targets:
    pool.addRequest(authData, transportTarget, varNames)
 
# Wait for responses or errors
pool.waitCompletion()

# Walk through responses
for errorIndication, errorStatus, errorIndex, varBinds in pool.getResponses():
    print('Response for %s from %s:' % (authData, transportTarget))
    if errorIndication:
        print(errorIndication)
    if errorStatus:
        print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBinds[int(errorIndex)-1][0] or '?'
            )
        )
    
    for oid, val in varBinds:
        if val is None:
            print(oid.prettyPrint())
        else:
            print('%s = %s' % (oid.prettyPrint(), val.prettyPrint()))
