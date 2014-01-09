# AES 192/256 bit encryption (Internet draft)
# http://tools.ietf.org/html/draft-blumenthal-aes-usm-04
from pysnmp.proto.secmod.eso.priv import aesbase

class Aes192(aesbase.AbstractAes):
    serviceID = (1, 3, 6, 1, 4, 1, 9, 12, 6, 1, 1)  # cusmAESCfb192PrivProtocol
    keySize = 24
