#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Olivier Verriest <verri@x25.pm>
# License: http://snmplabs.com/pysnmp/license.html
#
import sys
import hmac
try:
    from hashlib import sha224, sha256, sha384, sha512

except ImportError:

    class NotAvailable(object):
        def __call__(self, *args, **kwargs):
            raise errind.authenticationError

    sha224 = sha256 = sha384 = sha512 = NotAvailable()

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
    keyLengths = {
        sha224ServiceID: 28,
        sha256ServiceID: 32,
        sha384ServiceID: 48,
        sha512ServiceID: 64
    }
    digestLengths = {
        sha224ServiceID: 16,
        sha256ServiceID: 24,
        sha384ServiceID: 32,
        sha512ServiceID: 48
    }
    hashAlgorithms = {
        sha224ServiceID: sha224,
        sha256ServiceID: sha256,
        sha384ServiceID: sha384,
        sha512ServiceID: sha512
    }
    
    __ipad = [0x36] * 64
    __opad = [0x5C] * 64
    
    def __init__(self, oid):
        if oid not in self.hashAlgorithms:
            raise error.ProtocolError('No SHA-2 authentication algorithm %s available' % (oid,))
        self.__hashAlgo = self.hashAlgorithms[oid]
        self.__digestLength = self.digestLengths[oid]
        self.__placeHolder = univ.OctetString((0,) * self.__digestLength).asOctets()

    def hashPassphrase(self, authKey):
        return localkey.hashPassphrase(authKey, self.__hashAlgo)

    def localizeKey(self, authKey, snmpEngineID):
        return localkey.localizeKey(authKey, snmpEngineID, self.__hashAlgo)

    @property
    def digestLength(self):
        return self.__digestLength

    # 7.3.1
    def authenticateOutgoingMsg(self, authKey, wholeMsg):
        # 7.3.1.1
        location = wholeMsg.find(self.__placeHolder)
        if location == -1:
            raise error.ProtocolError('Can\'t locate digest placeholder')
        wholeHead = wholeMsg[:location]
        wholeTail = wholeMsg[location + self.__digestLength:]

        # 7.3.1.2, 7.3.1.3
        try:
            mac = hmac.new(authKey.asOctets(), wholeMsg, self.__hashAlgo)

        except errind.ErrorIndication:
            raise error.StatusInformation(errorIndication=sys.exc_info()[1])

        # 7.3.1.4
        mac = mac.digest()[:self.__digestLength]

        # 7.3.1.5 & 6
        return wholeHead + mac + wholeTail

    # 7.3.2
    def authenticateIncomingMsg(self, authKey, authParameters, wholeMsg):
        # 7.3.2.1 & 2
        if len(authParameters) != self.__digestLength:
            raise error.StatusInformation(
                errorIndication=errind.authenticationError
            )

        # 7.3.2.3
        location = wholeMsg.find(authParameters.asOctets())
        if location == -1:
            raise error.ProtocolError('Can\'t locate digest in wholeMsg')
        wholeHead = wholeMsg[:location]
        wholeTail = wholeMsg[location + self.__digestLength:]
        authenticatedWholeMsg = wholeHead + self.__placeHolder + wholeTail

        # 7.3.2.4
        try:
            mac = hmac.new(authKey.asOctets(), authenticatedWholeMsg, self.__hashAlgo)

        except errind.ErrorIndication:
            raise error.StatusInformation(errorIndication=sys.exc_info()[1])

        # 7.3.2.5
        mac = mac.digest()[:self.__digestLength]

        # 7.3.2.6
        if mac != authParameters:
            raise error.StatusInformation(
                errorIndication=errind.authenticationFailure
            )

        return authenticatedWholeMsg
