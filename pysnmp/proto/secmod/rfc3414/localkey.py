# Convert plaintext passphrase into a localized key
import md5

# RFC3414: A.2.1
def hashPassphrase(passphrase):
    md = md5.new()
    passLen = len(passphrase)
    count = passIndex = 0
    while count < 1048575:  # why rfc says 1048576?
        i = 0; passBuf = ''
        while i < 64:
            passBuf = passBuf + passphrase[passIndex % passLen]
            i = i + 1; passIndex = passIndex + 1;
        md.update(passBuf)
        count = count + 64
    return md.digest()

def localizeKey(passKey, snmpEngineId):
    return md5.new('%s%s%s' % (passKey, str(snmpEngineId), passKey)).digest()

def passwordToKeyMD5(passphrase, snmpEngineId):
    return localizeKey(hashPassphrase(passphrase), snmpEngineId)

# XXX
#     d, m = divmod(len(password))
#     prevM = count = 0
#     while count < 1048576:
#         i = 0
#         while i < 64:
#             md.update(password[prevM:] + password * (d-1) + \
#                       password[:prevM] + password[prevM:prevM+m])
#             prevM = m
            
#print map(lambda x: '%x' % ord(x), passwordToKeyMD5('maplesyrup', '\x00'*11+'\x02'))
import string

#print repr(passwordToKeyMD5('12345678', '\x80\x00\x07\xe5\x80<\x93eE\xdb_\x88B'))
#print string.join(map(lambda x: x, passwordToKeyMD5('12345678', '\x80\x00\x07\xe5\x80<\x93eE\xdb_\x88B')), '')
