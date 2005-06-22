# PDU v1/v2c two-way proxy
from pysnmp.proto import rfc3411
from pysnmp.proto.api import v1, v2c
from pysnmp.smi import exval

# 2.1.1

__v1ToV2ValueMap = {
    v1.Integer.tagSet: v2c.Integer32(),
    v1.OctetString.tagSet: v2c.OctetString(),
    v1.Null.tagSet: v2c.Null(),
    v1.ObjectIdentifier.tagSet: v2c.ObjectIdentifier(),
    v1.IpAddress.tagSet: v2c.IpAddress(),
    v1.Counter.tagSet: v2c.Counter32(),
    v1.Gauge.tagSet: v2c.Gauge32(),
    v1.TimeTicks.tagSet: v2c.TimeTicks(),
    v1.Opaque.tagSet: v2c.Opaque()
    }

__v2ToV1ValueMap = { # XXX do not re-create same-type items?
    v2c.Integer32.tagSet: v1.Integer(),
    v2c.OctetString.tagSet: v1.OctetString(),
    v2c.Null.tagSet: v1.Null(),
    v2c.ObjectIdentifier.tagSet: v1.ObjectIdentifier(),
    v2c.IpAddress.tagSet: v1.IpAddress(),
    v2c.Counter32.tagSet: v1.Counter(),
    v2c.Gauge32.tagSet: v1.Gauge(),
    v2c.TimeTicks.tagSet: v1.TimeTicks(),
    v2c.Opaque.tagSet: v1.Opaque()
    }

# PDU map

__v1ToV2PduMap = {
    v1.GetRequestPDU.tagSet: v2c.GetRequestPDU(),
    v1.GetNextRequestPDU.tagSet: v2c.GetNextRequestPDU(),
    v1.SetRequestPDU.tagSet: v2c.SetRequestPDU(),
    v1.GetResponsePDU.tagSet: v2c.ResponsePDU(),
    v1.TrapPDU.tagSet: v2c.SNMPv2TrapPDU()
    }

__v2ToV1PduMap = {
    v2c.GetRequestPDU.tagSet: v1.GetRequestPDU(),
    v2c.GetNextRequestPDU.tagSet: v1.GetNextRequestPDU(),
    v2c.SetRequestPDU.tagSet: v1.SetRequestPDU(),
    v2c.ResponsePDU.tagSet: v1.GetResponsePDU(),
    v2c.SNMPv2TrapPDU.tagSet: v1.TrapPDU(),
    v2c.GetBulkRequestPDU.tagSet: v1.GetNextRequestPDU() # 4.1.1
    }

# Trap map

__v1ToV2TrapMap = {
    0: (1,3,6,1,6,3,1,1,5,1),
    1: (1,3,6,1,6,3,1,1,5,2),
    2: (1,3,6,1,6,3,1,1,5,3),
    3: (1,3,6,1,6,3,1,1,5,4),
    4: (1,3,6,1,6,3,1,1,5,5),
    5: (1,3,6,1,6,3,1,1,5,6)
    }

__v2ToV1TrapMap = {
    (1,3,6,1,6,3,1,1,5,1): 0,
    (1,3,6,1,6,3,1,1,5,2): 1,
    (1,3,6,1,6,3,1,1,5,3): 2,
    (1,3,6,1,6,3,1,1,5,4): 3,
    (1,3,6,1,6,3,1,1,5,5): 4,
    (1,3,6,1,6,3,1,1,5,6): 5
    }

# 4.3

__v2ToV1ErrorMap = {
    0:  0,
    1:  1,
    5:  5,
    10: 3,
    9:  3,
    7:  3,
    8:  3,
    12: 3,
    6:  2,
    17: 2,
    11: 2,
    18: 2,
    13: 5,
    14: 5,
    15: 5,
    16: 2
    }

def v1ToV2(v1Pdu, origV2Pdu=None):
    pduType = v1Pdu.tagSet
    v2Pdu = __v1ToV2PduMap[pduType].clone()

    v2c.apiPDU.setDefaults(v2Pdu)
    
    if not rfc3411.notificationClassPDUs.has_key(pduType):
        v2Pdu.setComponentByPosition(  # req-id
            0, long(v1Pdu.getComponentByPosition(0))
            )

    v2VarBinds = []

    # 3.1
    if rfc3411.notificationClassPDUs.has_key(pduType):
        # 3.1.1
        sysUpTime = v1.apiTrapPDU.getTimeStamp(v1Pdu)

        # 3.1.2
        genericTrap = v1.apiTrapPDU.getGenericTrap(v1Pdu)
        if genericTrap == 6:
            snmpTrapOID = v1.apiTrapPDU.getEnterprise(v1Pdu) + (0,) + \
                          v1.apiTrapPDU.getSpecificTrap(v1Pdu)

        # 3.1.3
        else:
            snmpTrapOID = __v1ToV2TrapMap[int(genericTrap)]

        v2VarBinds.append((sysUpTime, None))
        v2VarBinds.append((snmpTrapOID, None))
        
        # 3.1.4 --> done below

    # Translate Var-Binds
    for oid, v1Val in v1.apiPDU.getVarBinds(v1Pdu):
        v2VarBinds.append(
            (oid, __v1ToV2ValueMap[v1Val.tagSet].clone(v1Val))
            )

    if rfc3411.responseClassPDUs.has_key(pduType):
        # 4.1.2.2 --> one-to-one mapping
        v2Pdu.setComponentByPosition( # err-status
            1, int(v1Pdu.getComponentByPosition(1))
            )
        v2Pdu.setComponentByPosition(  # err-index
            2, int(v1Pdu.getComponentByPosition(2))
            )

        # 4.1.2.1 --> no-op

    v2c.apiPDU.setVarBinds(v2Pdu, v2VarBinds)
        
    return v2Pdu

def v2ToV1(v2Pdu, origV1Pdu=None):
    pduType = v2Pdu.tagSet

    v1Pdu = __v2ToV1PduMap[pduType].clone()

    v2VarBinds = v2c.apiPDU.getVarBinds(v2Pdu)
    v1VarBinds = []

    # 3.2
    if rfc3411.notificationClassPDUs.has_key(pduType):
        # 3.2.1
        snmpTrapOID = tuple(v2VarBinds[0][0])
        if __v2ToV1TrapMap.has_key(snmpTrapOID):
            for oid, val in v2VarBinds:
                # snmpTrapEnterprise
                if oid == (1, 3, 6, 1, 6, 3, 1, 1, 4, 3, 0):
                    v1.apiTrapPDU.setEnterprise(v1Pdu, val)
                    break
            else:
                # snmpTraps
                v1.apiTrapPDU.setEnterprise(v1Pdu, (1, 3, 6, 1, 6, 3, 1, 1, 5))
        else:
            if snmpTrapOID[-2] == 0:
                v1.apiTrapPDU.setEnterprise(v1Pdu, snmpTrapOID[:-2])
            else:
                v1.apiTrapPDU.setEnterprise(v1Pdu, snmpTrapOID[:-1])

        # 3.2.2
        for oid, val in v2VarBinds:
            # snmpTrapAddress
            if oid == (1, 3, 6, 1, 6, 3, 18, 1, 3, 0):
                v1.apiTrapPDU.setAgentAddress(v1Pdu, val)
                break
        else:
            v1.apiTrapPDU.setAgentAddress(v1Pdu, '0.0.0.0')

        # 3.2.3
        if __v2ToV1TrapMap.has_key(snmpTrapOID):
            v1.apiTrapPDU.setGenericTrap(v1Pdu, __v2ToV1TrapMap[snmpTrapOID])
        else:
            v1.apiTrapPDU.setGenericTrap(v1Pdu, 0)

        # 3.2.4
        if __v2ToV1TrapMap.has_key(snmpTrapOID):
            v1.apiTrapPDU.setSpecificTrap(v1Pdu, 0)
        else:
            v1.apiTrapPDU.setSpecificTrap(v1Pdu, snmpTrapOID[-1])

        # 3.2.5
        v1.apiTrapPDU.setTimeStamp(v1Pdu, v2c.apiTrapPDU.getTimeStamp(v2Pdu))

        # 3.2.6 --> done below

    if rfc3411.responseClassPDUs.has_key(pduType):
        idx = len(v2VarBinds)-1
        while idx >= 0:
            # 4.1.2.1
            oid, val = v2VarBinds[idx]
            if v2c.Counter64.tagSet == val.tagSet:
                if origV1Pdu.tagSet == v1.GetRequestPDU.tagSet:
                    v1.apiPDU.setErrorStatus(v1Pdu, 2)
                    v1.apiPDU.setErrorIndex(v1Pdu, idx+1)
                    break
                elif origV1Pdu.tagSet == v1.GetNextRequestPDU.tagSet:
                    raise error.StatusInformation(idx=idx, pdu=v2Pdu)
                else:
                    raise error.ProtocolError('Counter64 on the way')

            # 4.1.2.2.1&2
            if exval.noSuchInstance.tagSet == val.tagSet or \
               exval.noSuchObject.tagSet == val.tagSet or \
               exval.endOfMibView.tagSet == val.tagSet:
                v1.apiPDU.setErrorStatus(v1Pdu, 2)
                v1.apiPDU.setErrorIndex(v1Pdu, idx+1)
                
            idx = idx - 1

        # 4.1.2.3.1
        v2ErrorStatus = v2c.apiPDU.getErrorStatus(v2Pdu)
        if v2ErrorStatus:
            v1.apiPDU.setErrorStatus(
                v1Pdu, __v2ToV1ErrorMap[int(v2ErrorStatus)]
                )
            v1.apiPDU.setErrorIndex(v1Pdu, v2c.apiPDU.getErrorIndex(v2Pdu))
            
    if not rfc3411.notificationClassPDUs.has_key(pduType):
        v1Pdu.setComponentByPosition(  # req-id
            0, v2Pdu.getComponentByPosition(0)
            )

    # Translate Var-Binds
    for oid, v2Val in v2VarBinds:
        v1VarBinds.append(
            (oid, __v2ToV1ValueMap[v2Val.tagSet].clone(v2Val))
            )

    v1.apiPDU.setVarBinds(v1Pdu, v1VarBinds)
    v1.apiPDU.setDefaults(v1Pdu)

    return v1Pdu

# XXX constants
