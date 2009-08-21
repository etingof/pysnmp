# Convert plaintext passphrase into a localized key
try:
    from hashlib import md5, sha1
except ImportError:
    import md5, sha
    md5 = md5.new
    sha1 = sha.new

# RFC3414: A.2.1
def hashPassphraseMD5(passphrase):
    md = md5()
    ringBuffer = passphrase * (64/len(passphrase)+1)
    ringBufferLen = len(ringBuffer)
    count = 0
    mark = 0
    while count < 16384:
        e = mark + 64
        if e < ringBufferLen:
            md.update(ringBuffer[mark:e])
            mark = e
        else:
            md.update(
                ringBuffer[mark:ringBufferLen] + ringBuffer[0:e-ringBufferLen]
                )
            mark = e-ringBufferLen
        count = count + 1
    return md.digest()

def localizeKeyMD5(passKey, snmpEngineId):
    return md5('%s%s%s' % (passKey, str(snmpEngineId), passKey)).digest()

def passwordToKeyMD5(passphrase, snmpEngineId):
    return localizeKeyMD5(hashPassphraseMD5(passphrase), snmpEngineId)

# RFC3414: A.2.2
def hashPassphraseSHA(passphrase):
    md = sha1()
    ringBuffer = passphrase * (64/len(passphrase)+1)
    ringBufferLen = len(ringBuffer)
    count = 0
    mark = 0
    while count < 16384:
        e = mark + 64
        if e < ringBufferLen:
            md.update(ringBuffer[mark:e])
            mark = e
        else:
            md.update(
                ringBuffer[mark:ringBufferLen] + ringBuffer[0:e-ringBufferLen]
                )
            mark = e-ringBufferLen
        count = count + 1
    return md.digest()

def localizeKeySHA(passKey, snmpEngineId):
    return sha1('%s%s%s' % (passKey, str(snmpEngineId), passKey)).digest()

def passwordToKeySHA(passphrase, snmpEngineId):
    return localizeKeySHA(hashPassphraseSHA(passphrase), snmpEngineId)
