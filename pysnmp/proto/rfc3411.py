from pysnmp.proto import rfc1157, rfc1905

__all__ = [
    'ReadClassMixIn', 'WriteClassMixIn', 'ResponseClassMixIn',
    'NotificationClassMixIn', 'InternalClassMixIn', 
    'ConfirmedClassMixIn', 'UnconfirmedClassMixIn'
    ]

# Functional PDU classification

class ReadClassMixIn: pass
class WriteClassMixIn: pass
class ResponseClassMixIn: pass
class NotificationClassMixIn: pass
class InternalClassMixIn: pass

# PDU classification based on whether a response is expected

class ConfirmedClassMixIn: pass
class UnconfirmedClassMixIn: pass

# Classify various PDU types    

__mixInMatrix = (
    # RFC1157 types
    (rfc1157.GetRequestPdu, (ReadClassMixIn, ConfirmedClassMixIn)),
    (rfc1157.GetNextRequestPdu, (ReadClassMixIn, ConfirmedClassMixIn)),
    (rfc1157.SetRequestPdu, (WriteClassMixIn, ConfirmedClassMixIn)),
    (rfc1157.GetResponsePdu, (ResponseClassMixIn, UnconfirmedClassMixIn)),
    (rfc1157.GetResponsePdu, ( ResponseClassMixIn, UnconfirmedClassMixIn)),
    (rfc1157.TrapPdu, (NotificationClassMixIn, UnconfirmedClassMixIn)),
    # RFC1905 types
    (rfc1905.GetRequestPdu, (ReadClassMixIn, ConfirmedClassMixIn)),
    (rfc1905.GetNextRequestPdu, (ReadClassMixIn, ConfirmedClassMixIn)),
    (rfc1905.GetBulkRequestPdu, (ReadClassMixIn, ConfirmedClassMixIn)),
    (rfc1905.SetRequestPdu, (WriteClassMixIn, ConfirmedClassMixIn)),
    (rfc1905.ResponsePdu, (ResponseClassMixIn, UnconfirmedClassMixIn)),
    (rfc1905.ReportPdu, (ResponseClassMixIn, UnconfirmedClassMixIn,
                         InternalClassMixIn)),
    (rfc1905.SnmpV2TrapPdu, (NotificationClassMixIn, UnconfirmedClassMixIn))
    )

for baseClass, mixIns in __mixInMatrix:
    for mixIn in mixIns:
        if mixIn not in baseClass.__bases__:
            baseClass.__bases__ = (mixIn, ) + baseClass.__bases__
