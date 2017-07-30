#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2017, Olivier Verriest <verri@x25.pm>
# License: http://pysnmp.sf.net/license.html
#
try:
    from hashlib import sha224, sha256, sha384, sha512
    import hmac
except ImportError:
    import logging
    logging.debug('SHA-2 HMAC authentication unavailable', exc_info=True)

from pyasn1.type import univ
from pysnmp.proto.secmod.rfc3414.auth import base
from pysnmp.proto.secmod.rfc3414 import localkey
from pysnmp.proto import errind, error

# 7.2.4

class HmacSha2(base.AbstractAuthenticationService):
    sha224ServiceID = (1, 3, 6, 1, 6, 3, 10, 1, 1, 4)  # usmHMAC128SHA224AuthProtocol
    sha256ServiceID = (1, 3, 6, 1, 6, 3, 10, 1, 1, 5)  # usmHMAC192SHA256AuthProtocol
    sha384ServiceID = (1, 3, 6, 1, 6, 3, 10, 1, 1, 6)  # usmHMAC256SHA384AuthProtocol
    sha512ServiceID = (1, 3, 6, 1, 6, 3, 10, 1, 1, 7)  # usmHMAC384SHA512AuthProtocol
    keyLength = {
        sha224ServiceID : 28,
        sha256ServiceID : 32,
        sha384ServiceID : 48,
        sha512ServiceID : 64
    }
    tagLength = {
        sha224ServiceID : 16,
        sha256ServiceID : 24,
        sha384ServiceID : 32,
        sha512ServiceID : 48
    }
    hashAlgo = {
        sha224ServiceID : sha224,
        sha256ServiceID : sha256,
        sha384ServiceID : sha384,
        sha512ServiceID : sha512
    }
    
    __ipad = [0x36] * 64
    __opad = [0x5C] * 64
    
    def __init__(self, oid):
        if not oid in HmacSha2.hashAlgo:
            raise error.ProtocolError('no such SHA-2 authentication algorithm', oid)
        self.__hashAlgo = HmacSha2.hashAlgo[oid]
        self.__tagLength = HmacSha2.tagLength[oid]
        self.__placeHolder = univ.OctetString((0,) * self.__tagLength).asOctets()

    def hashPassphrase(self, authKey):
        return localkey.hashPassphrase(authKey, self.__hashAlgo)

    def localizeKey(self, authKey, snmpEngineID):
        return localkey.localizeKey(authKey, snmpEngineID, self.__hashAlgo)

    def getTagLen(self):
        return self.__tagLength

    # 7.3.1
    def authenticateOutgoingMsg(self, authKey, wholeMsg):
        # 7.3.1.1
        l = wholeMsg.find(self.__placeHolder)
        if l == -1:
            raise error.ProtocolError('Can\'t locate digest placeholder')
        wholeHead = wholeMsg[:l]
        wholeTail = wholeMsg[l + self.__tagLength:]

        # 7.3.1.2, 7.3.1.3
        mac = hmac.new(authKey.asOctets(), wholeMsg, self.__hashAlgo)

        # 7.3.1.4
        mac = mac.digest()[:self.__tagLength]

        # 7.3.1.5 & 6
        return wholeHead + mac + wholeTail

    # 7.3.2
    def authenticateIncomingMsg(self, authKey, authParameters, wholeMsg):
        # 7.3.2.1 & 2
        if len(authParameters) != self.__tagLength:
            raise error.StatusInformation(
                errorIndication=errind.authenticationError
            )

        # 7.3.2.3
        l = wholeMsg.find(authParameters.asOctets())
        if l == -1:
            raise error.ProtocolError('Can\'t locate digest in wholeMsg')
        wholeHead = wholeMsg[:l]
        wholeTail = wholeMsg[l + self.__tagLength:]
        authenticatedWholeMsg = wholeHead + self.__placeHolder + wholeTail

        # 7.3.2.4
        mac = hmac.new(authKey.asOctets(), authenticatedWholeMsg, self.__hashAlgo)

        # 7.3.2.5
        mac = mac.digest()[:self.__tagLength]

        # 7.3.2.6
        if mac != authParameters:
            raise error.StatusInformation(
                errorIndication=errind.authenticationFailure
            )

        return authenticatedWholeMsg
