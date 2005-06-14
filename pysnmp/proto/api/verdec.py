from pyasn1.codec.ber import decoder

def decodeMessageVersion(wholeMsg):
    seq, wholeMsg = decoder.decode(wholeMsg, recursiveFlag=0)
    ver, wholeMsg = decoder.decode(wholeMsg, recursiveFlag=0)
    return ver
