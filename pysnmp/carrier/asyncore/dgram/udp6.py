# Implements asyncore-based UDP6 transport domain
try:
    from socket import AF_INET6
except:
    AF_INET6 = None
from pysnmp.carrier.asynsock.dgram.base import DgramSocketTransport

domainName = snmpUDP6Domain = (1, 3, 6, 1, 2, 1, 100, 1, 2)

class Udp6SocketTransport(DgramSocketTransport):
    sockFamily = AF_INET6

    def normalizeAddress(self, transportAddress):
        if '%' in transportAddress[0]:  # strip zone ID
            return (transportAddress[0].split('%')[0],
                    transportAddress[1],
                    0, # flowinfo
                    0) # scopeid
        else:
            return (transportAddress[0],
                    transportAddress[1],
                    0,  # flowinfo
                    0)  # scopeid
 
Udp6Transport = Udp6SocketTransport
