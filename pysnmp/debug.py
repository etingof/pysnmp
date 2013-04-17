import sys
import time
from pyasn1.compat.octets import octs2ints
from pysnmp import error
from pysnmp import __version__

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
flagApp      = 0x0200
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
    'app': flagApp,
    'all': flagAll
    }

class Debug:
    defaultPrinter = sys.stderr.write
    def __init__(self, *flags):
        self._flags = flagNone
        self._printer = self.defaultPrinter
        self('running pysnmp version %s' % __version__)
        for f in flags:
            inverse = f and f[0] in ('!', '~')
            if inverse:
                f = f[1:]
            try:
                if inverse:
                    self._flags &= ~flagMap[f]
                else:
                    self._flags |= flagMap[f]
            except KeyError:
                raise error.PySnmpError('bad debug flag %s' % f)
  
            self('debug category \'%s\' %s' % (f, inverse and 'disabled' or 'enabled'))
        
    def __str__(self):
        return 'logger %s, flags %x' % (self._printer, self._flags)
    
    def __call__(self, msg):
        self._printer('DBG: [%s]: %s\n' % (self.timestamp(), msg))

    def __and__(self, flag):
        return self._flags & flag

    def __rand__(self, flag):
        return flag & self._flags

    def timestamp(self):
        return time.strftime('%H:%M:%S', time.localtime()) + \
               '.%.3d' % int((time.time() % 1) * 1000)

# This will yield false from bitwise and with a flag, and save
# on unnecessary calls
logger = 0

def setLogger(l):
    global logger
    logger = l

def hexdump(octets):
    return ' '.join(
            [ '%s%.2X' % (n%16 == 0 and ('\n%.5d: ' % n) or '', x) 
              for n,x in zip(range(len(octets)), octs2ints(octets)) ]
        )
