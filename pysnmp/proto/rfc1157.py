"""Implementation of SNMP v.1 (RFC1157)"""
from time import time
from pysnmp.asn1 import univ, tags, subtypes
from pysnmp.proto import rfc1155, error
import pysnmp.asn1.error

__all__ = [
    'Version', 'Community', 'RequestId', 'ErrorStatus', 'ErrorIndex',
    'VarBind', 'VarBindList', 'GetRequestPdu', 'GetNextRequestPdu',
    'GetResponsePdu', 'SetRequestPdu', 'Enterprise', 'AgentAddr',
    'GenericTrap', 'SpecificTrap', 'TimeStamp', 'TrapPdu', 'Pdus',
    'Message'
    ]

class Version(univ.Integer):
    subtypeConstraints = ( subtypes.SingleValueConstraint(0), )
    initialValue = 0
    namedValues = univ.Integer.namedValues.clone(('version-1', 0))
    
class Community(univ.OctetString):
    initialValue = 'public'

class InitialRequestIdMixIn:
    # Singular source of req IDs
    globalRequestId = 1000 - long(((time() / 100) % 1) * 1000)
    def initialValue(self):
        try:
            self.set(InitialRequestIdMixIn.globalRequestId)
        except pysnmp.asn1.error.ValueConstraintError:
            self.set(InitialRequestIdMixIn.globalRequestId)
        else:
            InitialRequestIdMixIn.globalRequestId = InitialRequestIdMixIn.globalRequestId + 1
            
class RequestId(InitialRequestIdMixIn, univ.Integer): pass
    
class ErrorStatus(univ.Integer):
    initialValue = 0
    subtypeConstraints = ( subtypes.ValueRangeConstraint(0, 5), )
    namedValues = univ.Integer.namedValues.clone(
        ('noError', 0), ('tooBig', 1), ('noSuchName', 2),
        ('badValue', 3), ('readOnly', 4), ('genError', 5)
        )
    pduErrors = [
        '(noError) No Error',
        '(tooBig) Response message would have been too large',
        '(noSuchName) There is no such variable name in this MIB',
        '(badValue) The value given has the wrong type or length',
        '(readOnly) No modifications allowed to this object',
        '(genError) A general failure occured'
        ]
    
    def __str__(self):
        return '%s: %d (%s)' % (
            self.__class__.__name__, self.get(), self.pduErrors[self.get()]
            )

class ErrorIndex(univ.Integer):
    initialValue = 0

class VarBind(univ.Sequence):
    # Bind structure
    protoComponents = {
        'name': rfc1155.ObjectName(),
        'value': rfc1155.ObjectSyntax()
        }
    protoSequence = ( 'name', 'value' )
        
class VarBindList(univ.SequenceOf):
    protoComponent = VarBind()
    
class RequestPdu(univ.Sequence):
    tagSet = univ.Sequence.tagSet.clone(
        tagClass=tags.tagClassContext
        )
    # PDU structure
    protoComponents = {
        'request_id': RequestId(),
        'error_status': ErrorStatus(),
        'error_index': ErrorIndex(),
        'variable_bindings': VarBindList()
        }
    protoSequence = (
        'request_id', 'error_status', 'error_index', 'variable_bindings'
        )

class GetRequestPdu(RequestPdu):
    tagSet = RequestPdu.tagSet.clone(tagId=0x00)

class GetNextRequestPdu(RequestPdu):
    tagSet = RequestPdu.tagSet.clone(tagId=0x01)

class GetResponsePdu(RequestPdu):
    tagSet = RequestPdu.tagSet.clone(tagId=0x02)

class SetRequestPdu(RequestPdu):
    tagSet = RequestPdu.tagSet.clone(tagId=0x03)

# Trap stuff

class Enterprise(univ.ObjectIdentifier):
    initialValue = (1,3,6,1,1,2,3,4,1)

class AgentAddr(rfc1155.NetworkAddress): pass

class GenericTrap(univ.Integer):
    initialValue = 0
    subtypeConstraints = ( subtypes.ValueRangeConstraint(0, 6), )
    namedValues = univ.Integer.namedValues.clone(
        ('coldStart', 0), ('warmStart', 1), ('linkDown', 2),
        ('linkUp', 3), ('authenticationFailure', 4), ('egpNeighborLoss', 5),
        ('enterpriseSpecific', 6)
        )

class SpecificTrap(univ.Integer):
    initialValue = 0

class TimeStamp(rfc1155.TimeTicks):
    def __init__(self, value=int(time())):
        rfc1155.TimeTicks.__init__(self, value)

class TrapPdu(univ.Sequence):
    tagSet = univ.Sequence.tagSet.clone(
        tagClass=tags.tagClassContext, tagId=0x04
        )
    # PDU structure
    protoComponents = {
        'enterprise': Enterprise(),
        'agent_addr': AgentAddr(),
        'generic_trap': GenericTrap(),
        'specific_trap': SpecificTrap(),
        'time_stamp': TimeStamp(),
        'variable_bindings': VarBindList()
        }
    protoSequence = (
        'enterprise', 'agent_addr', 'generic_trap',
        'specific_trap', 'time_stamp', 'variable_bindings'
        )

class Pdus(univ.Choice):
    protoComponents = {
        'get_request': GetRequestPdu(),
        'get_next_request': GetNextRequestPdu(),
        'get_response': GetResponsePdu(),
        'set_request': SetRequestPdu(),
        'trap': TrapPdu()
        }
    protoSequence = (
        'get_request', 'get_next_request', 'get_response',
        'set_request', 'trap'
        )
    
class Message(univ.Sequence):
    protoComponents = {
        'version': Version(),
        'community': Community(),
        'pdu': Pdus()
        }
    protoSequence = ( 'version', 'community', 'pdu' )
