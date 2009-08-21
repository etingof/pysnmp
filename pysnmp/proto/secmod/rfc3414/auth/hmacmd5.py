try:
    from hashlib import md5
except ImportError:
    import md5
    md5 = md5.new                    
import string
from pysnmp.proto.secmod.rfc3414.auth import base
from pysnmp.proto import error

_twelveZeros = '\x00'*12
_fortyEightZeros = '\x00'*48

# rfc3414: 6.2.4

class HmacMd5(base.AbstractAuthenticationService):
    serviceID = (1, 3, 6, 1, 6, 3, 10, 1, 1, 2)  # usmHMACMD5AuthProtocol
    __ipad = [0x36]*64
    __opad = [0x5C]*64

    # 6.3.1
    def authenticateOutgoingMsg(self, authKey, wholeMsg):
        # Here we expect calling secmod to indicate where the digest
        # should be in the substrate. Also, it pre-sets digest placeholder
        # so we hash wholeMsg out of the box.
        # Yes, that's ugly but that's rfc...
        l = string.find(wholeMsg, _twelveZeros)
        if l == -1:
            raise error.ProtocolError('Cant locate digest placeholder')
        wholeHead = wholeMsg[:l]
        wholeTail = wholeMsg[l+12:]

        # 6.3.1.1 

        # 6.3.1.2a
        extendedAuthKey = map(ord, str(authKey) + _fortyEightZeros)

        # 6.3.1.2b --> noop

        # 6.3.1.2c
        k1 = string.join(
            map(lambda x,y: chr(x^y), extendedAuthKey, self.__ipad), ''
            )

        # 6.3.1.2d --> noop

        # 6.3.1.2e
        k2 = string.join(
            map(lambda x,y: chr(x^y), extendedAuthKey, self.__opad), ''
            )
        
        # 6.3.1.3
        d1 = md5(k1+wholeMsg).digest()
        
        # 6.3.1.4
        d2 = md5(k2+d1).digest()
        mac = d2[:12]

        # 6.3.1.5 & 6
        return '%s%s%s' % (wholeHead, mac, wholeTail)

    # 6.3.2
    def authenticateIncomingMsg(self, authKey, authParameters, wholeMsg):
        # 6.3.2.1 & 2
        if len(authParameters) != 12:
            raise error.StatusInformation(
                errorIndication='authenticationError'
                )

        # 6.3.2.3
        l = string.find(wholeMsg, str(authParameters))
        if l == -1:
            raise error.ProtocolError('Cant locate digest in wholeMsg')
        wholeHead = wholeMsg[:l]
        wholeTail = wholeMsg[l+12:]
        authenticatedWholeMsg = '%s%s%s' % (
            wholeHead, _twelveZeros, wholeTail
            )

        # 6.3.2.4a
        extendedAuthKey = map(ord, str(authKey) + _fortyEightZeros)

        # 6.3.2.4b --> noop
        
        # 6.3.2.4c
        k1 = string.join(
            map(lambda x,y: chr(x^y), extendedAuthKey, self.__ipad), ''
            )

        # 6.3.2.4d --> noop

        # 6.3.2.4e
        k2 = string.join(
            map(lambda x,y: chr(x^y), extendedAuthKey, self.__opad), ''
            )

        # 6.3.2.5a
        d1 = md5(k1+authenticatedWholeMsg).digest()

        # 6.3.2.5b
        d2 = md5(k2+d1).digest()
        
        # 6.3.2.5c
        mac = d2[:12]
         
        # 6.3.2.6
        if mac != authParameters:
            raise error.StatusInformation(
                errorIndication='authenticationFailure'
                )

        return authenticatedWholeMsg
