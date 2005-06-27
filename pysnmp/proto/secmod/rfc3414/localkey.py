# Convert plaintext passphrase into a localized key
import md5

# RFC3414: A.2.1
def hashPassphrase(passphrase):
    md = md5.new()
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

def localizeKey(passKey, snmpEngineId):
    return md5.new('%s%s%s' % (passKey, str(snmpEngineId), passKey)).digest()

def passwordToKeyMD5(passphrase, snmpEngineId):
    return localizeKey(hashPassphrase(passphrase), snmpEngineId)
