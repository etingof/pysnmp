from string import split, digits
from pysnmp.smi import error
from pyasn1.type import constraint, namedval
from pysnmp import debug

OctetString, Integer, ObjectIdentifier = mibBuilder.importSymbols(
    'ASN1', 'OctetString', 'Integer', 'ObjectIdentifier'
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

    def prettyOut(self, value):  # override asn1 type method
        """Implements DISPLAY-HINT evaluation"""
        if self.displayHint and (
            self.__integer.isSuperTypeOf(self) or
            self.__unsigned32.isSuperTypeOf(self) or
            self.__timeticks.isSuperTypeOf(self) or
            self.__counter32.isSuperTypeOf(self) or
            self.__counter64.isSuperTypeOf(self)
            ):
            t, f = apply(lambda t, f=0: (t, f), split(self.displayHint, '-'))
            if t == 'x':
                return '0x%x' % value
            elif t == 'd':
                try:
                    return '%.*f' % (int(f), float(value)/pow(10, int(f)))
                except StandardError, why:
                    raise error.SmiError(
                        'float num evaluation error: %s' % why
                    )
            elif t == 'o':
                return '0%o' % value
            elif t == 'b':
                v = value; r = ['B']
                while v:
                    r.insert(0, '%d' % (v&0x01))
                    v = v>>1
                return join(r, '')
            else:
                raise error.SmiError(
                    'Unsupported numeric type spec: %s' % t
                    )
        elif self.displayHint and self.__octetString.isSuperTypeOf(self):
            r = ''
            v = str(value)
            d = self.displayHint
            while v and d:
                # 1
                if d[0] == '*':
                    repeatIndicator = repeatCount = int(v[0])
                    d = d[1:]; v = v[1:]
                else:
                    repeatCount = 1; repeatIndicator = None
                    
                # 2
                octetLength = ''
                while d and d[0] in digits:
                    octetLength = octetLength + d[0]
                    d = d[1:]
                try:
                    octetLength = int(octetLength)
                except StandardError, why:
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
                if d and d[0] not in digits and d[0] != '*':
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
                        r = r + v[:octetLength]
                    elif displayFormat in ('x', 'd', 'o'):
                        n = 0L; vv = v[:octetLength]
                        while vv:
                            n = n << 8
                            try:
                                n = n | ord(vv[0])
                                vv = vv[1:]
                            except StandardError, why:
                                raise error.SmiError(
                                    'Display format eval failure: %s: %s'
                                    % (vv, why)
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
        elif self.displayHint and self.__objectIdentifier.isSuperTypeOf(self):
            return str(value)
        else:
            return str(value)

#         elif self.bits:
#             try:
#                 return self.bits[value]
#             except StandardError, why:
#                 raise error.SmiError(
#                     'Enumeratin resolution failure for %s: %s' % (self, why)
#                     )

# XXX
#    def prettyIn(self, value):
#        # XXX parse TC syntax
#        return str(value)

class DisplayString(TextualConvention, OctetString):
    subtypeSpec = OctetString.subtypeSpec+constraint.ValueSizeConstraint(0,255)
    displayHint = "255a"

class PhysAddress(TextualConvention, OctetString):
    displayHint = "1x:"

class MacAddress(TextualConvention, OctetString):
    subtypeSpec = OctetString.subtypeSpec+constraint.ValueSizeConstraint(6,6)
    displayHint = "1x:"
    fixedLength = 6

class TruthValue(Integer, TextualConvention):
    subtypeSpec = Integer.subtypeSpec+constraint.SingleValueConstraint(1, 2)
    namedValues = namedval.NamedValues(('true', 1), ('false', 2))
    
class TestAndIncr(Integer, TextualConvention):
    subtypeSpec = Integer.subtypeSpec+constraint.ValueRangeConstraint(0, 2147483647L)
    defaultValue = 0
    def smiWrite(self, name, value, idx):
        if value != self:
            raise error.InconsistentValueError(idx=idx, name=name)
        value = value + 1
        if value > 2147483646:
            value = 0
        return self.clone(value)

class AutonomousType(ObjectIdentifier, TextualConvention): pass
class InstancePointer(ObjectIdentifier, TextualConvention):
    status = 'obsolete'
class VariablePointer(ObjectIdentifier, TextualConvention): pass
class RowPointer(ObjectIdentifier, TextualConvention): pass
    
class RowStatus(Integer, TextualConvention):
    """A special kind of scalar MIB variable responsible for
       MIB table row creation/destruction.
    """
    subtypeSpec = Integer.subtypeSpec+constraint.SingleValueConstraint(0, 1, 2, 3, 4, 5, 6)
    namedValues = namedval.NamedValues(
        ('notExists', 0), ('active', 1), ('notInService', 2), ('notReady', 3),
        ('createAndGo', 4), ('createAndWait', 5), ('destroy', 6)
        )
    # Known row states
    stNotExists, stActive, stNotInService, stNotReady, \
                 stCreateAndGo, stCreateAndWait, stDestroy = range(7)
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
    defaultValue = stNotExists
    pendingError = None
    
    def smiWrite(self, name, value, idx):
        # Run through states transition matrix, resolve new instance value
        err, val = self.stateMatrix.get(
            (self.clone(value), int(self)), (error.MibOperationError, None)
            )
        debug.logger & debug.flagIns and debug.logger('RowStatus state resolution: %s, %s -> %s, %s' % (value, int(self), err, val))
        if val is None:
            val = self
        else:
            val = self.clone(val)
        if err is not None:
            err = err(
                msg='Exception at row state transition %s->%s' % (self, value),
                idx=idx
                )
            val.smiSetPendingError(err)
        return val

    def smiCreate(self, name, value, idx):
        return self.smiWrite(name, value, idx)
        
    def smiRaisePendingError(self):
        if self.pendingError:
            err, self.pendingError = self.pendingError, None
            raise err
    def smiSetPendingError(self, err):
        self.pendingError = err
        
class TimeStamp(TimeTicks, TextualConvention): pass

class TimeInterval(Integer, TextualConvention):
    subtypeSpec = Integer.subtypeSpec+constraint.ValueRangeConstraint(0, 2147483647L)

class DateAndTime(TextualConvention, OctetString):
    subtypeSpec = OctetString.subtypeSpec+constraint.ValueSizeConstraint(8, 11)
    displayHint = "2d-1d-1d,1d:1d:1d.1d,1a1d:1d"

class StorageType(Integer, TextualConvention):
    subtypeSpec = Integer.subtypeSpec+constraint.SingleValueConstraint(1, 2, 3, 4, 5)
    namedValues = namedval.NamedValues(
        ('other', 1), ('volatile', 2), ('nonVolatile', 3),
        ('permanent', 4), ('readOnly', 5)
        )

class TDomain(ObjectIdentifier, TextualConvention): pass

class TAddress(OctetString, TextualConvention):
    subtypeSpec = OctetString.subtypeSpec+constraint.ValueSizeConstraint(1, 255)

mibBuilder.exportSymbols(
    'SNMPv2-TC', TextualConvention=TextualConvention, DisplayString=DisplayString,
    PhysAddress=PhysAddress, MacAddress=MacAddress, TruthValue=TruthValue,
    TestAndIncr=TestAndIncr, AutonomousType=AutonomousType,
    InstancePointer=InstancePointer, VariablePointer=VariablePointer,
    RowPointer=RowPointer, RowStatus=RowStatus, TimeStamp=TimeStamp,
    TimeInterval=TimeInterval, DateAndTime=DateAndTime, StorageType=StorageType,
    TDomain=TDomain, TAddress=TAddress
    )
