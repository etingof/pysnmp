#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2017, Ilya Etingof <etingof@gmail.com>
# License: http://pysnmp.sf.net/license.html
#
import sys
import inspect
import string
from pysnmp.smi.error import *
from pysnmp import debug
from pyasn1.compat import octets
from pyasn1.type.base import Asn1Item

OctetString, Integer, ObjectIdentifier = mibBuilder.importSymbols(
    'ASN1', 'OctetString', 'Integer', 'ObjectIdentifier'
)

NamedValues, = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")

(ConstraintsIntersection, ConstraintsUnion, SingleValueConstraint,
 ValueRangeConstraint, ValueSizeConstraint) = mibBuilder.importSymbols(
    "ASN1-REFINEMENT", "ConstraintsIntersection", "ConstraintsUnion",
    "SingleValueConstraint", "ValueRangeConstraint", "ValueSizeConstraint"
)

Counter32, Unsigned32, TimeTicks, Counter64 = mibBuilder.importSymbols(
    'SNMPv2-SMI', 'Counter32', 'Unsigned32', 'TimeTicks', 'Counter64'
)


class TextualConvention(object):
    displayHint = ''
    status = 'current'
    description = ''
    reference = ''
    bits = ()
    __integer = Integer()
    __unsigned32 = Unsigned32()
    __timeticks = TimeTicks()
    __octetString = OctetString()

    def getDisplayHint(self):
        return self.displayHint

    def getStatus(self):
        return self.status

    def getDescription(self):
        return self.description

    def getReference(self):
        return self.reference

    def getValue(self):
        return self.clone()

    def setValue(self, value):
        return self.clone(value)

    def prettyOut(self, value):  # override asn1 type method
        """Implements DISPLAY-HINT evaluation"""
        if self.displayHint and (self.__integer.isSuperTypeOf(self) and not self.getNamedValues() or
                                 self.__unsigned32.isSuperTypeOf(self) or
                                 self.__timeticks.isSuperTypeOf(self)):
            _ = lambda t, f=0: (t, f)
            displayHintType, decimalPrecision = _(*self.displayHint.split('-'))
            if displayHintType == 'x':
                return '0x%x' % value
            elif displayHintType == 'd':
                try:
                    return '%.*f' % (int(decimalPrecision), float(value) / pow(10, int(decimalPrecision)))
                except Exception:
                    raise SmiError(
                        'float evaluation error: %s' % sys.exc_info()[1]
                    )
            elif displayHintType == 'o':
                return '0%o' % value
            elif displayHintType == 'b':
                runningValue = value
                outputValue = ['B']
                while runningValue:
                    outputValue.insert(0, '%d' % (runningValue & 0x01))
                    runningValue >>= 1
                return ''.join(outputValue)
            else:
                raise SmiError(
                    'Unsupported numeric type spec "%s" at %s' % (displayHintType, self.__class__.__name__)
                )
        elif self.displayHint and self.__octetString.isSuperTypeOf(self):
            outputValue = ''
            runningValue = OctetString(value).asOctets()
            displayHint = self.displayHint
            while runningValue and displayHint:
                # 1
                if displayHint[0] == '*':
                    repeatIndicator = repeatCount = octets.oct2int(runningValue[0])
                    displayHint = displayHint[1:]
                    runningValue = runningValue[1:]
                else:
                    repeatCount = 1
                    repeatIndicator = None

                # 2
                octetLength = ''
                while displayHint and displayHint[0] in string.digits:
                    octetLength += displayHint[0]
                    displayHint = displayHint[1:]

                # length is manatory, but people ignore that
                if not octetLength:
                    octetLength = len(runningValue)

                try:
                    octetLength = int(octetLength)
                except Exception:
                    raise SmiError(
                        'Bad octet length: %s' % octetLength
                    )

                if not displayHint:
                    raise SmiError(
                        'Short octet length: %s' % self.displayHint
                    )

                # 3
                displayFormat = displayHint[0]
                displayHint = displayHint[1:]

                # 4
                if displayHint and displayHint[0] not in string.digits and displayHint[0] != '*':
                    displaySep = displayHint[0]
                    displayHint = displayHint[1:]
                else:
                    displaySep = ''

                # 5
                if displayHint and displaySep and repeatIndicator is not None:
                    repeatTerminator = displayHint[0]
                    displaySep = ''
                    displayHint = displayHint[1:]
                else:
                    repeatTerminator = None

                while repeatCount:
                    repeatCount -= 1
                    if displayFormat == 'a':
                        outputValue += runningValue[:octetLength].decode('ascii', 'ignore')
                    elif displayFormat == 't':
                        outputValue += runningValue[:octetLength].decode('utf-8', 'ignore')
                    elif displayFormat in ('x', 'd', 'o'):
                        number = 0
                        numberString = runningValue[:octetLength]
                        while numberString:
                            number <<= 8
                            try:
                                number |= octets.oct2int(numberString[0])
                                numberString = numberString[1:]
                            except Exception:
                                raise SmiError(
                                    'Display format eval failure: %s: %s'
                                    % (numberString, sys.exc_info()[1])
                                )
                        if displayFormat == 'x':
                            outputValue += '%02x' % number
                        elif displayFormat == 'o':
                            outputValue += '%03o' % number
                        else:
                            outputValue += '%d' % number
                    else:
                        raise SmiError(
                            'Unsupported display format char: %s' %
                            displayFormat
                        )
                    if runningValue and repeatTerminator:
                        outputValue += repeatTerminator
                    runningValue = runningValue[octetLength:]
                if runningValue and displaySep:
                    outputValue += displaySep
                if not displayHint:
                    displayHint = self.displayHint

            return outputValue

        for base in inspect.getmro(self.__class__):
            if not issubclass(base, TextualConvention) and issubclass(base, Asn1Item):
                return base.prettyOut(self, value)

        raise SmiError('TEXTUAL-CONVENTION has no underlying SNMP base type')

    def prettyIn(self, value):  # override asn1 type method
        """Implements DISPLAY-HINT parsing into base SNMP value

        Proper parsing seems impossible due to ambiguities.
        Here we are truing to do our best, but be prepared
        for failures on complicated DISPLAY-HINTs.

        Keep in mind that this parser only works with "text"
        input meaning `unicode` (Py2) or `str` (Py3).
        """
        for base in inspect.getmro(self.__class__):
            if not issubclass(base, TextualConvention) and issubclass(base, Asn1Item):
                break
        else:
            raise SmiError('TEXTUAL-CONVENTION has no underlying SNMP base type')

        if self.displayHint and (self.__integer.isSuperTypeOf(self) and self.getNamedValues() or
                                 self.__unsigned32.isSuperTypeOf(self) or
                                 self.__timeticks.isSuperTypeOf(self)):
            value = str(value)

            _ = lambda t, f=0: (t, f)
            displayHintType, decimalPrecision = _(*self.displayHint.split('-'))
            if displayHintType == 'x' and (value.startswith('0x') or value.startswith('-0x')):
                try:
                    if value.startswith('-'):
                        return base.prettyIn(self, -int(value[3:], 16))
                    else:
                        return base.prettyIn(self, int(value[2:], 16))
                except Exception:
                    raise SmiError(
                        'integer evaluation error: %s' % sys.exc_info()[1]
                    )
            elif displayHintType == 'd':
                try:
                    return base.prettyIn(self, int(float(value) * 10**int(decimalPrecision)))
                except Exception:
                    raise SmiError(
                        'float evaluation error: %s' % sys.exc_info()[1]
                    )
            elif displayHintType == 'o' and (value.startswith('0') or value.startswith('-0')):
                try:
                    return base.prettyIn(self, int(value, 8))
                except Exception:
                    raise SmiError(
                        'octal evaluation error: %s' % sys.exc_info()[1]
                    )
            elif displayHintType == 'b' and (value.startswith('B') or value.startswith('-B')):
                negative = value.startswith('-')
                if negative:
                    value = value[2:]
                else:
                    value = value[1:]
                value = [x != '0' and 1 or 0 for x in value]
                binValue = 0
                while value:
                    binValue <<= value[0]
                    del value[0]
                return base.prettyIn(self, binValue)
            else:
                raise SmiError(
                    'Unsupported numeric type spec "%s" at %s' % (displayHintType, self.__class__.__name__)
                )

        elif self.displayHint and self.__octetString.isSuperTypeOf(self):
            numBase = {
                'x': 16,
                'd': 10,
                'o': 8
            }
            numDigits = {
                'x': octets.str2octs(string.hexdigits),
                'o': octets.str2octs(string.octdigits),
                'd': octets.str2octs(string.digits)
            }

            # how do we know if object is initialized with display-hint
            # formatted text? based on "text" input maybe?
            if octets.isStringType(value) and not octets.isOctetsType(value):
                value = base.prettyIn(self, value)
            else:
                return base.prettyIn(self, value)

            outputValue = octets.str2octs('')
            runningValue = value
            displayHint = self.displayHint
            while runningValue and displayHint:
                # 1 this information is totally lost, just fail explicitly
                if displayHint[0] == '*':
                    raise SmiError(
                        'Can\'t parse "*" in DISPLAY-HINT (%s)' % self.__class__.__name__
                    )

                # 2 this becomes ambiguous when it comes to rendered value
                octetLength = ''
                while displayHint and displayHint[0] in string.digits:
                    octetLength += displayHint[0]
                    displayHint = displayHint[1:]

                # length is mandatory but people ignore that
                if not octetLength:
                    octetLength = len(runningValue)

                try:
                    octetLength = int(octetLength)
                except Exception:
                    raise SmiError(
                        'Bad octet length: %s' % octetLength
                    )

                if not displayHint:
                    raise SmiError(
                        'Short octet length: %s' % self.displayHint
                    )

                # 3
                displayFormat = displayHint[0]
                displayHint = displayHint[1:]

                # 4 this is the lifesaver -- we could use it as an anchor
                if displayHint and displayHint[0] not in string.digits and displayHint[0] != '*':
                    displaySep = displayHint[0]
                    displayHint = displayHint[1:]
                else:
                    displaySep = ''

                # 5 is probably impossible to support

                if displayFormat in ('a', 't'):
                    outputValue += runningValue[:octetLength]
                elif displayFormat in numBase:
                    if displaySep:
                        guessedOctetLength = runningValue.find(octets.str2octs(displaySep))
                        if guessedOctetLength == -1:
                            guessedOctetLength = len(runningValue)
                    else:
                        for idx in range(len(runningValue)):
                            if runningValue[idx] not in numDigits[displayFormat]:
                                guessedOctetLength = idx
                                break
                        else:
                            guessedOctetLength = len(runningValue)

                    try:
                        num = int(octets.octs2str(runningValue[:guessedOctetLength]), numBase[displayFormat])
                    except Exception:
                        raise SmiError(
                            'Display format eval failure: %s: %s'
                            % (runningValue[:guessedOctetLength], sys.exc_info()[1])
                        )

                    num_as_bytes = []
                    if num:
                        while num:
                            num_as_bytes.append(num & 0xFF)
                            num >>= 8
                    else:
                        num_as_bytes = [0]

                    while len(num_as_bytes) < octetLength:
                        num_as_bytes.append(0)

                    num_as_bytes.reverse()

                    outputValue += octets.ints2octs(num_as_bytes)

                    if displaySep:
                        guessedOctetLength += 1

                    octetLength = guessedOctetLength
                else:
                    raise SmiError(
                        'Unsupported display format char: %s' %
                        displayFormat
                    )

                runningValue = runningValue[octetLength:]

                if not displayHint:
                    displayHint = self.displayHint

            return base.prettyIn(self, outputValue)

        else:
            return base.prettyIn(self, value)


class DisplayString(TextualConvention, OctetString):
    subtypeSpec = OctetString.subtypeSpec + ValueSizeConstraint(0, 255)
    displayHint = "255a"


class PhysAddress(TextualConvention, OctetString):
    displayHint = "1x:"


class MacAddress(TextualConvention, OctetString):
    subtypeSpec = OctetString.subtypeSpec + ValueSizeConstraint(6, 6)
    displayHint = "1x:"
    fixedLength = 6


class TruthValue(TextualConvention, Integer):
    subtypeSpec = Integer.subtypeSpec + SingleValueConstraint(1, 2)
    namedValues = NamedValues(('true', 1), ('false', 2))


class TestAndIncr(TextualConvention, Integer):
    subtypeSpec = Integer.subtypeSpec + ValueRangeConstraint(0, 2147483647)
    defaultValue = 0

    def setValue(self, value):
        if value is not None:
            if value != self:
                raise InconsistentValueError()
            value += 1
            if value > 2147483646:
                value = 0
        return self.clone(self, value)


class AutonomousType(TextualConvention, ObjectIdentifier):
    pass


class InstancePointer(TextualConvention, ObjectIdentifier):
    status = 'obsolete'


class VariablePointer(TextualConvention, ObjectIdentifier):
    pass


class RowPointer(TextualConvention, ObjectIdentifier):
    pass


class RowStatus(TextualConvention, Integer):
    """A special kind of scalar MIB variable responsible for
       MIB table row creation/destruction.
    """
    subtypeSpec = Integer.subtypeSpec + SingleValueConstraint(0, 1, 2, 3, 4, 5, 6)
    namedValues = NamedValues(
        ('notExists', 0), ('active', 1), ('notInService', 2), ('notReady', 3),
        ('createAndGo', 4), ('createAndWait', 5), ('destroy', 6)
    )
    # Known row states
    (stNotExists, stActive, stNotInService,
     stNotReady, stCreateAndGo, stCreateAndWait,
     stDestroy) = list(range(7))

    # States transition matrix (see RFC-1903)
    stateMatrix = {
        # (new-state, current-state)  ->  (error, new-state)
        (stCreateAndGo, stNotExists): (RowCreationWanted, stActive),
        (stCreateAndGo, stNotReady): (InconsistentValueError, stNotReady),
        (stCreateAndGo, stNotInService): (InconsistentValueError, stNotInService),
        (stCreateAndGo, stActive): (InconsistentValueError, stActive),
        #
        (stCreateAndWait, stNotExists): (RowCreationWanted, stActive),
        (stCreateAndWait, stNotReady): (InconsistentValueError, stNotReady),
        (stCreateAndWait, stNotInService): (InconsistentValueError, stNotInService),
        (stCreateAndWait, stActive): (InconsistentValueError, stActive),
        #
        (stActive, stNotExists): (InconsistentValueError, stNotExists),
        (stActive, stNotReady): (InconsistentValueError, stNotReady),
        (stActive, stNotInService): (None, stActive),
        (stActive, stActive): (None, stActive),
        #
        (stNotInService, stNotExists): (InconsistentValueError, stNotExists),
        (stNotInService, stNotReady): (InconsistentValueError, stNotReady),
        (stNotInService, stNotInService): (None, stNotInService),
        (stNotInService, stActive): (None, stActive),
        #
        (stDestroy, stNotExists): (RowDestructionWanted, stNotExists),
        (stDestroy, stNotReady): (RowDestructionWanted, stNotExists),
        (stDestroy, stNotInService): (RowDestructionWanted, stNotExists),
        (stDestroy, stActive): (RowDestructionWanted, stNotExists),
        # This is used on instantiation
        (stNotExists, stNotExists): (None, stNotExists)
    }

    def setValue(self, value):
        value = self.clone(value)

        # Run through states transition matrix,
        # resolve new instance value
        excValue, newState = self.stateMatrix.get(
            (value.hasValue() and value or self.stNotExists,
             self.hasValue() and self or self.stNotExists),
            (MibOperationError, None)
        )
        newState = self.clone(newState)

        debug.logger & debug.flagIns and debug.logger(
            'RowStatus state change from %r to %r produced new state %r, error indication %r' % (
                self, value, newState, excValue))

        if excValue is not None:
            excValue = excValue(
                msg='Exception at row state transition from %r to %r yields state %r and exception' % (
                    self, value, newState), syntax=newState
            )
            raise excValue

        return newState


class TimeStamp(TextualConvention, TimeTicks):
    pass


class TimeInterval(TextualConvention, Integer):
    subtypeSpec = Integer.subtypeSpec + ValueRangeConstraint(0, 2147483647)


class DateAndTime(TextualConvention, OctetString):
    subtypeSpec = OctetString.subtypeSpec + ValueSizeConstraint(8, 11)
    displayHint = "2d-1d-1d,1d:1d:1d.1d,1a1d:1d"


class StorageType(TextualConvention, Integer):
    subtypeSpec = Integer.subtypeSpec + SingleValueConstraint(1, 2, 3, 4, 5)
    namedValues = NamedValues(
        ('other', 1), ('volatile', 2), ('nonVolatile', 3),
        ('permanent', 4), ('readOnly', 5)
    )


class TDomain(TextualConvention, ObjectIdentifier):
    pass


class TAddress(TextualConvention, OctetString):
    subtypeSpec = OctetString.subtypeSpec + ValueSizeConstraint(1, 255)


mibBuilder.exportSymbols(
    'SNMPv2-TC', TextualConvention=TextualConvention,
    DisplayString=DisplayString, PhysAddress=PhysAddress,
    MacAddress=MacAddress, TruthValue=TruthValue, TestAndIncr=TestAndIncr,
    AutonomousType=AutonomousType, InstancePointer=InstancePointer,
    VariablePointer=VariablePointer, RowPointer=RowPointer,
    RowStatus=RowStatus, TimeStamp=TimeStamp, TimeInterval=TimeInterval,
    DateAndTime=DateAndTime, StorageType=StorageType, TDomain=TDomain,
    TAddress=TAddress
)
