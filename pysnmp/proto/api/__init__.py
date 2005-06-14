from pysnmp.proto.api import v1, v2c, verdec

# Protocol versions
protoVersion1 = 0
protoVersion2c = 1
protoModules = { protoVersion1: v1, protoVersion2c: v2c }

decodeMessageVersion = verdec.decodeMessageVersion
