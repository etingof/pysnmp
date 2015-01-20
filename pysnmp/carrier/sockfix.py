#
# Add some of the missing socket module symbols
#
import socket

symbols = {
    'IP_PKTINFO':       8,
    'IP_TRANSPARENT':   19,
    'SOL_IPV6':         41,
    'IPV6_RECVPKTINFO': 49,
    'IPV6_PKTINFO':     50
}

for symbol in symbols:
    if not hasattr(socket, symbol):
        setattr(socket, symbol, symbols[symbol])
