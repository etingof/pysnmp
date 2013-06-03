# AES 192/256 bit encryption (Internet draft)
# http://tools.ietf.org/html/draft-blumenthal-aes-usm-04
from pysnmp.proto.secmod.rfc3826.priv import aes
from pysnmp.proto.secmod.rfc3414.auth import hmacmd5, hmacsha
from pysnmp.proto.secmod.rfc3414 import localkey
from pysnmp.proto import error

class Aes192(aes.Aes):
    serviceID = (1, 3, 6, 1, 4, 1, 9, 12, 6, 1, 1)  # cusmAESCfb192PrivProtocol
    keySize = 24

    # 3.1.2.1
    def localizeKey(self, authProtocol, privKey, snmpEngineID):
        if authProtocol == hmacmd5.HmacMd5.serviceID:
            localPrivKey = localkey.localizeKeyMD5(privKey, snmpEngineID)
            localPrivKey = localPrivKey + localkey.localizeKeyMD5(
                localPrivKey, snmpEngineID
                )
        elif authProtocol == hmacsha.HmacSha.serviceID:
            localPrivKey = localkey.localizeKeySHA(privKey, snmpEngineID)
            localPrivKey = localPrivKey + localkey.localizeKeySHA(
                localPrivKey, snmpEngineID
                )
        else:
            raise error.ProtocolError(
                'Unknown auth protocol %s' % (authProtocol,)
                )
        return localPrivKey[:24]
