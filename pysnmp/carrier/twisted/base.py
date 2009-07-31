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

class AbstractTwistedTransport:
    """Base Twisted Transport, to be used with TwistedDispatcher"""
    def __init__(self):
        self._writeQ = []

    # AbstractTwistedTransport API
    
    def registerCbFun(self, cbFun):
        self._cbFun = cbFun

    def unregisterCbFun(self):
        self._cbFun = None

    def closeTransport(self):
        self.unregisterCbFun()
