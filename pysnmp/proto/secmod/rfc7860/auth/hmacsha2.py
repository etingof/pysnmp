#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Olivier Verriest <verri@x25.pm>
# License: http://snmplabs.com/pysnmp/license.html
#
import hmac
try:
    from hashlib import sha224
    from hashlib import sha256
    from hashlib import sha384
    from hashlib import sha512

except ImportError:

    class NotAvailable(object):
        def __call__(self, *args, **kwargs):
            raise errind.authenticationError

    sha224 = sha256 = sha384 = sha512 = NotAvailable()

from pysnmp.proto.secmod.rfc3414.auth import base
from pysnmp.proto.secmod.rfc3414 import localkey
from pysnmp.proto import errind, error

from pyasn1.type import univ

# 7.2.4

class HmacSha2(base.AbstractAuthenticationService):
    # usmHMAC128SHA224AuthProtocol
    SHA224_SERVICE_ID = (1, 3, 6, 1, 6, 3, 10, 1, 1, 4)

    # usmHMAC192SHA256AuthProtocol
    SHA256_SERVICE_ID = (1, 3, 6, 1, 6, 3, 10, 1, 1, 5)

    # usmHMAC256SHA384AuthProtocol
    SHA384_SERVICE_ID = (1, 3, 6, 1, 6, 3, 10, 1, 1, 6)

    # usmHMAC384SHA512AuthProtocol
    SHA512_SERVICE_ID = (1, 3, 6, 1, 6, 3, 10, 1, 1, 7)

    KEY_LENGTH = {
        SHA224_SERVICE_ID: 28,
        SHA256_SERVICE_ID: 32,
        SHA384_SERVICE_ID: 48,
        SHA512_SERVICE_ID: 64
    }

    DIGEST_LENGTH = {
        SHA224_SERVICE_ID: 16,
        SHA256_SERVICE_ID: 24,
        SHA384_SERVICE_ID: 32,
        SHA512_SERVICE_ID: 48
    }

    HASH_ALGORITHM = {
        SHA224_SERVICE_ID: sha224,
        SHA256_SERVICE_ID: sha256,
        SHA384_SERVICE_ID: sha384,
        SHA512_SERVICE_ID: sha512
    }
    
    IPAD = [0x36] * 64
    OPAD = [0x5C] * 64
    
    def __init__(self, oid):
        if oid not in self.HASH_ALGORITHM:
            raise error.ProtocolError(
                'No SHA-2 authentication algorithm %s available' % (oid,))

        self._hashAlgo = self.HASH_ALGORITHM[oid]
        self._digestLength = self.DIGEST_LENGTH[oid]
        self._placeHolder = univ.OctetString(
            (0,) * self._digestLength).asOctets()

    def hashPassphrase(self, authKey):
        return localkey.hashPassphrase(authKey, self._hashAlgo)

    def localizeKey(self, authKey, snmpEngineID):
        return localkey.localizeKey(authKey, snmpEngineID, self._hashAlgo)

    @property
    def digestLength(self):
        return self._digestLength

    # 7.3.1
    def authenticateOutgoingMsg(self, authKey, wholeMsg):
        # 7.3.1.1
        location = wholeMsg.find(self._placeHolder)
        if location == -1:
            raise error.ProtocolError('Cannot locate digest placeholder')

        wholeHead = wholeMsg[:location]
        wholeTail = wholeMsg[location + self._digestLength:]

        # 7.3.1.2, 7.3.1.3
        try:
            mac = hmac.new(authKey.asOctets(), wholeMsg, self._hashAlgo)

        except errind.ErrorIndication as exc:
            raise error.StatusInformation(errorIndication=exc)

        # 7.3.1.4
        mac = mac.digest()[:self._digestLength]

        # 7.3.1.5 & 6
        return wholeHead + mac + wholeTail

    # 7.3.2
    def authenticateIncomingMsg(self, authKey, authParameters, wholeMsg):
        # 7.3.2.1 & 2
        if len(authParameters) != self._digestLength:
            raise error.StatusInformation(
                errorIndication=errind.authenticationError)

        # 7.3.2.3
        location = wholeMsg.find(authParameters.asOctets())
        if location == -1:
            raise error.ProtocolError('Cannot locate digest in wholeMsg')

        wholeHead = wholeMsg[:location]
        wholeTail = wholeMsg[location + self._digestLength:]
        authenticatedWholeMsg = wholeHead + self._placeHolder + wholeTail

        # 7.3.2.4
        try:
            mac = hmac.new(authKey.asOctets(), authenticatedWholeMsg, self._hashAlgo)

        except errind.ErrorIndication as exc:
            raise error.StatusInformation(errorIndication=exc)

        # 7.3.2.5
        mac = mac.digest()[:self._digestLength]

        # 7.3.2.6
        if mac != authParameters:
            raise error.StatusInformation(
                errorIndication=errind.authenticationFailure)

        return authenticatedWholeMsg
