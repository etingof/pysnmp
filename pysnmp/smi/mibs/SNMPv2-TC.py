#
# WARNING: some of the classes below are manually implemented
#
import sys
from pysnmp.smi import error
from pysnmp import debug

OctetString, Integer, ObjectIdentifier = mibBuilder.importSymbols(
    'ASN1', 'OctetString', 'Integer', 'ObjectIdentifier'
    )
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsIntersection, ConstraintsUnion, SingleValueConstraint,
  ValueRangeConstraint, ValueSizeConstraint, ) = mibBuilder.importSymbols(
    "ASN1-REFINEMENT", "ConstraintsIntersection", "ConstraintsUnion",
    "SingleValueConstraint", "ValueRangeConstraint", "ValueSizeConstraint"
    )
Counter32, Unsigned32, TimeTicks, Counter64 = mibBuilder.importSymbols(
    'SNMPv2-SMI', 'Counter32', 'Unsigned32', 'TimeTicks', 'Counter64'
    )

class TextualConvention:
    displayHint = ''
    status = 'current'
    description = ''
    reference = ''
    bits = ()
    __integer = Integer()
    __counter32 = Counter32()
    __unsigned32 = Unsigned32()
    __timeticks = TimeTicks()
    __counter64 = Counter64()
    __octetString = OctetString()
    __objectIdentifier = ObjectIdentifier()
    def getDisplayHint(self): return self.displayHint
    def getStatus(self): return self.status
    def getDescription(self): return self.description
    def getReference(self): return self.reference

    def getValue(self): return self.clone()
    def setValue(self, value): return self.clone(value)

    def prettyOut(self, value):  # override asn1 type method
        """Implements DISPLAY-HINT evaluation"""
        if self.displayHint and (
            self.__integer.isSuperTypeOf(self) or
            self.__unsigned32.isSuperTypeOf(self) or
            self.__timeticks.isSuperTypeOf(self) or
            self.__counter32.isSuperTypeOf(self) or
            self.__counter64.isSuperTypeOf(self)
            ):
            _ = lambda t, f=0: (t, f)
            t, f = _(*self.displayHint.split('-'))
            if t == 'x':
                return '0x%x' % value
            elif t == 'd':
                try:
                    return '%.*f' % (int(f), float(value)/pow(10, int(f)))
                except Exception:
                    raise error.SmiError(
                        'float num evaluation error: %s' % sys.exc_info()[1]
                    )
            elif t == 'o':
                return '0%o' % value
            elif t == 'b':
                v = value; r = ['B']
                while v:
                    r.insert(0, '%d' % (v&0x01))
                    v = v>>1
                return ''.join(r)
            else:
                raise error.SmiError(
                    'Unsupported numeric type spec: %s' % t
                    )
        elif self.displayHint and self.__octetString.isSuperTypeOf(self):
            r = ''
            v = self.__class__(value).asNumbers()
            d = self.displayHint
            while v and d:
                # 1
                if d[0] == '*':
                    repeatIndicator = repeatCount = v[0]
                    d = d[1:]; v = v[1:]
                else:
                    repeatCount = 1; repeatIndicator = None
                    
                # 2
                octetLength = ''
                while d and d[0] in '0123456789':
                    octetLength = octetLength + d[0]
                    d = d[1:]
                try:
                    octetLength = int(octetLength)
                except Exception:
                    raise error.SmiError(
                        'Bad octet length: %s' % octetLength
                        )                    
                if not d:
                    raise error.SmiError(
                        'Short octet length: %s' % self.displayHint
                        )
                # 3
                displayFormat = d[0]
                d = d[1:]

                # 4
                if d and d[0] not in '0123456789' and d[0] != '*':
                    displaySep = d[0]
                    d = d[1:]
                else:
                    displaySep = ''

                # 5
                if d and displaySep and repeatIndicator is not None:
                    repeatTerminator = d[0]
                    displaySep = ''
                    d = d[1:]
                else:
                    repeatTerminator = None

                while repeatCount:
                    repeatCount = repeatCount - 1
                    # 't' stands for UTF-8, does it need any special support?
                    if displayFormat == 'a' or displayFormat == 't':
                        r = r + ''.join([ chr(x) for x in v[:octetLength] ])
                    elif displayFormat in ('x', 'd', 'o'):
                        n = 0; vv = v[:octetLength]
                        while vv:
                            n = n << 8
                            try:
                                n = n | vv[0]
                                vv = vv[1:]
                            except Exception:
                                raise error.SmiError(
                                    'Display format eval failure: %s: %s'
                                    % (vv, sys.exc_info()[1])
                                    )
                        if displayFormat == 'x':
                            r = r + '%02x' % n
                        elif displayFormat == 'o':
                            r = r + '%03o' % n
                        else:
                            r = r + '%d' % n
                    else:
                        raise error.SmiError(
                            'Unsupported display format char: %s' % \
                            displayFormat
                            )
                    if v and repeatTerminator:
                        r = r + repeatTerminator
                    v = v[octetLength:]
                if v and displaySep:
                    r = r + displaySep
                if not d:
                    d = self.displayHint
#             if d:
#                 raise error.SmiError(
#                     'Unparsed display hint left: %s' % d
#                     )
            return r
        elif self.__objectIdentifier.isSuperTypeOf(self):
            return self.__objectIdentifier.prettyOut(value)
        elif self.__octetString.isSuperTypeOf(self):
            return self.__octetString.prettyOut(value)
        else:
            return str(value)

#         elif self.bits:
#             try:
#                 return self.bits[value]
#             except Exception:
#                 raise error.SmiError(
#                     'Enumeratin resolution failure for %s: %s' % (self, sys.exc_info()[1])
#                     )

# XXX
#    def prettyIn(self, value):
#        # XXX parse TC syntax
#        return str(value)

class DisplayString(TextualConvention, OctetString):
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(0,255)
    displayHint = "255a"

class PhysAddress(TextualConvention, OctetString):
    displayHint = "1x:"

class MacAddress(TextualConvention, OctetString):
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(6,6)
    displayHint = "1x:"
    fixedLength = 6

class TruthValue(Integer, TextualConvention):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(1, 2)
    namedValues = NamedValues(('true', 1), ('false', 2))
    
class TestAndIncr(Integer, TextualConvention):
    subtypeSpec = Integer.subtypeSpec+ValueRangeConstraint(0, 2147483647)
    defaultValue = 0
    def setValue(self, value):
        if value is not None:
            if value != self:
                raise error.InconsistentValueError()
            value = value + 1
            if value > 2147483646:
                value = 0
        return self.clone(self, value)

class AutonomousType(ObjectIdentifier, TextualConvention): pass
class InstancePointer(ObjectIdentifier, TextualConvention):
    status = 'obsolete'
class VariablePointer(ObjectIdentifier, TextualConvention): pass
class RowPointer(ObjectIdentifier, TextualConvention): pass
    
class RowStatus(Integer, TextualConvention):
    """A special kind of scalar MIB variable responsible for
       MIB table row creation/destruction.
    """
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(0, 1, 2, 3, 4, 5, 6)
    namedValues = NamedValues(
        ('notExists', 0), ('active', 1), ('notInService', 2), ('notReady', 3),
        ('createAndGo', 4), ('createAndWait', 5), ('destroy', 6)
        )
    # Known row states
    stNotExists, stActive, stNotInService, stNotReady, \
                 stCreateAndGo, stCreateAndWait, stDestroy = list(range(7))
    # States transition matrix (see RFC-1903)
    stateMatrix = {
        # (new-state, current-state)  ->  (error, new-state)
        ( stCreateAndGo, stNotExists ): (
        error.RowCreationWanted, stActive
        ),
        ( stCreateAndGo, stNotReady ): (
        error.InconsistentValueError, stNotReady
        ),
        ( stCreateAndGo, stNotInService ): (
        error.InconsistentValueError, stNotInService
        ),
        ( stCreateAndGo, stActive ): (
        error.InconsistentValueError, stActive
        ),
        #
        ( stCreateAndWait, stNotExists ): (
        error.RowCreationWanted, stActive
        ),
        ( stCreateAndWait, stNotReady ): (
        error.InconsistentValueError, stNotReady
        ),
        ( stCreateAndWait, stNotInService ): (
        error.InconsistentValueError, stNotInService
        ),
        ( stCreateAndWait, stActive ): (
        error.InconsistentValueError, stActive
        ),
        #
        ( stActive, stNotExists ): (
        error.InconsistentValueError, stNotExists
        ),
        ( stActive, stNotReady ): (
        error.InconsistentValueError, stNotReady
        ),
        ( stActive, stNotInService ): (
        None, stActive
        ),
        ( stActive, stActive ): (
        None, stActive
        ),
        #
        ( stNotInService, stNotExists ): (
        error.InconsistentValueError, stNotExists
        ),
        ( stNotInService, stNotReady ): (
        error.InconsistentValueError, stNotReady
        ),
        ( stNotInService, stNotInService ): (
        None, stNotInService
        ),
        ( stNotInService, stActive ): (
        None, stActive
        ),
        #
        ( stDestroy, stNotExists ): (
        error.RowDestructionWanted, stNotExists
        ),
        ( stDestroy, stNotReady ): (
        error.RowDestructionWanted, stNotExists
        ),
        ( stDestroy, stNotInService ): (
        error.RowDestructionWanted, stNotExists
        ),
        ( stDestroy, stActive ): (
        error.RowDestructionWanted, stNotExists
        ),
        # This is used on instantiation
        ( stNotExists, stNotExists ): (
        None, stNotExists
        )
        }
    
    def setValue(self, value):
        value = self.clone(value)

        # Run through states transition matrix, 
        # resolve new instance value
        excValue, newState = self.stateMatrix.get(
            (value.hasValue() and value or self.stNotExists,
             self.hasValue() and self or self.stNotExists),
            (error.MibOperationError, None)
        )
        newState = self.clone(newState)

        debug.logger & debug.flagIns and debug.logger('RowStatus state change from %r to %r produced new state %r, error indication %r' % (self, value, newState, excValue))

        if excValue is not None:
            excValue = excValue(
                msg='Exception at row state transition from %r to %r yields state %r and exception' % (self, value, newState), syntax=newState
            )
            raise excValue

        return newState

class TimeStamp(TimeTicks, TextualConvention): pass

class TimeInterval(Integer, TextualConvention):
    subtypeSpec = Integer.subtypeSpec+ValueRangeConstraint(0, 2147483647)

class DateAndTime(TextualConvention, OctetString):
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(8, 11)
    displayHint = "2d-1d-1d,1d:1d:1d.1d,1a1d:1d"

class StorageType(Integer, TextualConvention):
    subtypeSpec = Integer.subtypeSpec+SingleValueConstraint(1, 2, 3, 4, 5)
    namedValues = NamedValues(
        ('other', 1), ('volatile', 2), ('nonVolatile', 3),
        ('permanent', 4), ('readOnly', 5)
        )

class TDomain(ObjectIdentifier, TextualConvention): pass

class TAddress(OctetString, TextualConvention):
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(1, 255)

mibBuilder.exportSymbols(
    'SNMPv2-TC', TextualConvention=TextualConvention, DisplayString=DisplayString,
    PhysAddress=PhysAddress, MacAddress=MacAddress, TruthValue=TruthValue,
    TestAndIncr=TestAndIncr, AutonomousType=AutonomousType,
    InstancePointer=InstancePointer, VariablePointer=VariablePointer,
    RowPointer=RowPointer, RowStatus=RowStatus, TimeStamp=TimeStamp,
    TimeInterval=TimeInterval, DateAndTime=DateAndTime, StorageType=StorageType,
    TDomain=TDomain, TAddress=TAddress
    )
