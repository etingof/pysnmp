import sys
from pysnmp import error

flagNone     = 0x0000
flagIO       = 0x0001
flagDsp      = 0x0002
flagMP       = 0x0004
flagSM       = 0x0008
flagBld      = 0x0010
flagMIB      = 0x0020
flagIns      = 0x0040
flagACL      = 0x0080
flagPrx      = 0x0100
flagAll      = 0xffff

flagMap = {
    'io': flagIO,
    'dsp': flagDsp,
    'msgproc': flagMP,
    'secmod': flagSM,
    'mibbuild': flagBld,
    'mibview': flagMIB,
    'mibinstrum': flagIns,
    'acl': flagACL,
    'proxy': flagPrx,    
    'all': flagAll
    }

class Debug:
    defaultPrinter = sys.stderr.write
    def __init__(self, *flags):
        self._flags = flagNone
        self._printer = self.defaultPrinter
        for f in flags:
            if not flagMap.has_key(f):
                raise error.PySnmpError('bad debug flag %s' % f)
            self._flags = self._flags | flagMap[f]
            self('debug category %s enabled' % f)
        
    def __str__(self):
        return 'logger %s, flags %x' % (self._printer, self._flags)
    
    def __call__(self, msg):
        self._printer('DBG: %s\n' % msg)

    def __and__(self, flag):
        return self._flags & flag

    def __rand__(self, flag):
        return flag & self._flags

logger = Debug()

def setLogger(l):
    global logger
    logger = l
