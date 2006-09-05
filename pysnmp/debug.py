import sys

flagNone     = 0x0000
flagIO       = 0x0001
flagDsp      = 0x0002
flagMP       = 0x0004
flagSM       = 0x0008
flagSMI      = 0x0010
flagAll      = 0xffff

logger = None

def __defaultLogger(flag, msg):
    if (flags & flag):
        sys.stderr.write('*** [%x] %s\n' % (flag, msg))

def setLogger(f):
    global logger
    logger = f

flags = flagNone

def setFlags(*f):
    global flags, logger
    flags = reduce(lambda x,y: x|y, f, flagNone)
    if flags and not logger:
        logger = __defaultLogger

