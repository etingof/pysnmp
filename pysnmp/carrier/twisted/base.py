#
#  Copyright (C) 2008 Truelite Srl <info@truelite.it>
#  Author: Filippo Giunchedi <filippo@truelite.it>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License Version 2
#  as published by the Free Software Foundation
#
#  Description: twisted DatagramProtocol UDP transport
#
from pysnmp.carrier.twisted.dispatch import TwistedDispatcher
from pysnmp.carrier.base import AbstractTransport

class AbstractTwistedTransport(AbstractTransport):
    protoTransportDispatcher = TwistedDispatcher
    """Base Twisted Transport, to be used with TwistedDispatcher"""
    def __init__(self):
        self._writeQ = []
