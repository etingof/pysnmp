#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
import logging

from pyasn1.compat.octets import octs2ints

from pysnmp import __version__
from pysnmp import error

FLAG_NONE = 0x0000
FLAG_IO = 0x0001
FLAG_DSP = 0x0002
FLAG_MP = 0x0004
FLAG_SM = 0x0008
FLAG_BLD = 0x0010
FLAG_MIB = 0x0020
FLAG_INS = 0x0040
FLAG_ACL = 0x0080
FLAG_PRX = 0x0100
FLAG_APP = 0x0200
FLAG_ALL = 0xffff

FLAG_MAP = {
    'io': FLAG_IO,
    'dsp': FLAG_DSP,
    'msgproc': FLAG_MP,
    'secmod': FLAG_SM,
    'mibbuild': FLAG_BLD,
    'mibview': FLAG_MIB,
    'mibinstrum': FLAG_INS,
    'acl': FLAG_ACL,
    'proxy': FLAG_PRX,
    'app': FLAG_APP,
    'all': FLAG_ALL
}


class Printer(object):
    def __init__(self, logger=None, handler=None, formatter=None):
        if logger is None:
            logger = logging.getLogger('pysnmp')

        logger.setLevel(logging.DEBUG)

        if handler is None:
            handler = logging.StreamHandler()

        if formatter is None:
            formatter = logging.Formatter('%(asctime)s %(name)s: %(message)s')

        handler.setFormatter(formatter)
        handler.setLevel(logging.DEBUG)

        logger.addHandler(handler)

        self.__logger = logger

    def __call__(self, msg):
        self.__logger.debug(msg)

    def __str__(self):
        return '<python built-in logging>'


if hasattr(logging, 'NullHandler'):
    NullHandler = logging.NullHandler

else:
    # Python 2.6
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass


class Debug(object):
    DEFAULT_PRINTER = None

    def __init__(self, *flags, **options):
        self._flags = FLAG_NONE

        if options.get('printer') is not None:
            self._printer = options.get('printer')

        elif self.DEFAULT_PRINTER is not None:
            self._printer = self.DEFAULT_PRINTER

        else:
            if 'loggerName' in options:
                # route our logs to parent logger
                self._printer = Printer(
                    logger=logging.getLogger(options['loggerName']),
                    handler=NullHandler())

            else:
                self._printer = Printer()

        self('running pysnmp version %s' % __version__)

        for flag in flags:
            negate = flag and flag[0] in ('!', '~')
            if negate:
                flag = flag[1:]

            try:
                if negate:
                    self._flags &= ~FLAG_MAP[flag]

                else:
                    self._flags |= FLAG_MAP[flag]

            except KeyError:
                raise error.PySnmpError('bad debug flag %s' % flag)

            self('debug category "%s" '
                 '%s' % (flag, negate and 'disabled' or 'enabled'))

    def __str__(self):
        return 'logger %s, flags %x' % (self._printer, self._flags)

    def __call__(self, msg):
        self._printer(msg)

    def __and__(self, flag):
        return self._flags & flag

    def __rand__(self, flag):
        return flag & self._flags


# This will yield false from bitwise and with a flag, and save
# on unnecessary calls
logger = 0


def setLogger(l):
    global logger
    logger = l


def hexdump(octets):
    return ' '.join(
        '%s%.2X' % (n % 16 == 0 and ('\n%.5d: ' % n) or '', x)
        for n, x in zip(range(len(octets)), octs2ints(octets)))
