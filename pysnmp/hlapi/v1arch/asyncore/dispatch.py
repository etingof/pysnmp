#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pysnmp.carrier.asyncore.dispatch import AsyncoreDispatcher
from pysnmp.hlapi.v1arch.dispatch import AbstractSnmpDispatcher

__all__ = ['SnmpDispatcher']


class SnmpDispatcher(AbstractSnmpDispatcher):
    protoDispatcher = AsyncoreDispatcher
