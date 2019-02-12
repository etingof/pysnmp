#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
import sys
import traceback

from pyasn1.error import PyAsn1Error
from pyasn1.type import univ

from pysnmp import cache
from pysnmp import debug
from pysnmp.proto import rfc1902
from pysnmp.smi import error
from pysnmp.smi import exval
from pysnmp.smi.indices import OidOrderedDict

Integer, ObjectIdentifier = mibBuilder.importSymbols(
    "ASN1", "Integer", "ObjectIdentifier"
)

(ConstraintsIntersection, ConstraintsUnion, SingleValueConstraint,
 ValueRangeConstraint, ValueSizeConstraint) = mibBuilder.importSymbols(
    "ASN1-REFINEMENT", "ConstraintsIntersection", "ConstraintsUnion",
    "SingleValueConstraint", "ValueRangeConstraint", "ValueSizeConstraint"
)

# syntax of objects

OctetString = rfc1902.OctetString
Bits = rfc1902.Bits
Integer32 = rfc1902.Integer32
IpAddress = rfc1902.IpAddress
Counter32 = rfc1902.Counter32
Gauge32 = rfc1902.Gauge32
Unsigned32 = rfc1902.Unsigned32
TimeTicks = rfc1902.TimeTicks
Opaque = rfc1902.Opaque
Counter64 = rfc1902.Counter64
Null = rfc1902.Null


class ExtUTCTime(OctetString):
    subtypeSpec = (OctetString.subtypeSpec +
                   ConstraintsUnion(ValueSizeConstraint(11, 11),
                                    ValueSizeConstraint(13, 13)))


# MIB tree foundation class

class MibNode(object):
    """MIB object base.

    Logically binds object identifier, which addresses MIB object in MIB tree,
    with MIB symbol which identifies MIB object within its MIB module.

    Serves as a foundation for more specialized MIB objects.
    """
    label = ''

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.name)

    def getName(self):
        return self.name

    def getLabel(self):
        return self.label

    def setLabel(self, label):
        self.label = label
        return self

    def clone(self, name=None):
        myClone = self.__class__(self.name)
        if name is not None:
            myClone.name = name
        if self.label is not None:
            myClone.label = self.label
        return myClone


# definitions for information modules

class ModuleIdentity(MibNode):
    status = 'current'
    lastUpdated = ''
    organization = ''
    contactInfo = ''
    description = ''
    revisions = ()
    revisionsDescriptions = ()

    def getStatus(self):
        return self.status

    def setStatus(self, v):
        self.status = v
        return self

    def getLastUpdated(self):
        return self.lastUpdated

    def setLastUpdated(self, v):
        self.lastUpdated = v
        return self

    def getOrganization(self):
        return self.organization

    def setOrganization(self, v):
        self.organization = v
        return self

    def getContactInfo(self):
        return self.contactInfo

    def setContactInfo(self, v):
        self.contactInfo = v
        return self

    def getDescription(self):
        return self.description

    def setDescription(self, v):
        self.description = v
        return self

    def getRevisions(self):
        return self.revisions

    def setRevisions(self, args):
        self.revisions = args
        return self

    def getRevisionsDescriptions(self):
        return self.revisionsDescriptions

    def setRevisionsDescriptions(self, args):
        self.revisionsDescriptions = args
        return self

    def asn1Print(self):
        return """\
MODULE-IDENTITY
  LAST-UPDATED %s
  ORGANIZATION "%s"
  CONTACT-INFO "%s"
  DESCRIPTION "%s"
  %s""" % (self.getLastUpdated(),
           self.getOrganization(),
           self.getContactInfo(),
           self.getDescription(),
           ''.join(['REVISION "%s"\n' % x for x in self.getRevisions()]))


class ObjectIdentity(MibNode):
    status = 'current'
    description = ''
    reference = ''

    def getStatus(self):
        return self.status

    def setStatus(self, v):
        self.status = v
        return self

    def getDescription(self):
        return self.description

    def setDescription(self, v):
        self.description = v
        return self

    def getReference(self):
        return self.reference

    def setReference(self, v):
        self.reference = v
        return self

    def asn1Print(self):
        return """\
OBJECT-IDENTITY
  STATUS %s
  DESCRIPTION "%s"
  REFERENCE "%s"
""" % (self.getStatus(),
       self.getDescription(),
       self.getReference())


# definition for objects

class NotificationType(MibNode):
    objects = ()
    status = 'current'
    description = ''
    reference = ''

    def getObjects(self):
        return self.objects

    def setObjects(self, *args, **kwargs):
        if kwargs.get('append'):
            self.objects += args
        else:
            self.objects = args
        return self

    def getStatus(self):
        return self.status

    def setStatus(self, v):
        self.status = v
        return self

    def getDescription(self):
        return self.description

    def setDescription(self, v):
        self.description = v
        return self

    def getReference(self):
        return self.reference

    def setReference(self, v):
        self.reference = v
        return self

    def asn1Print(self):
        return """\
NOTIFICATION-TYPE
  OBJECTS { %s }
  STATUS %s
  DESCRIPTION "%s"
  REFERENCE "%s"
""" % (', '.join([x for x in self.getObjects()]),
           self.getStatus(),
           self.getDescription(),
           self.getReference())


class MibIdentifier(MibNode):
    @staticmethod
    def asn1Print():
        return 'OBJECT IDENTIFIER'


class ObjectType(MibNode):
    units = ''
    maxAccess = 'not-accessible'
    status = 'current'
    description = ''
    reference = ''

    def __init__(self, name, syntax=None):
        MibNode.__init__(self, name)
        self.syntax = syntax

    # XXX
    def __eq__(self, other):
        return self.syntax == other

    def __ne__(self, other):
        return self.syntax != other

    def __lt__(self, other):
        return self.syntax < other

    def __le__(self, other):
        return self.syntax <= other

    def __gt__(self, other):
        return self.syntax > other

    def __ge__(self, other):
        return self.syntax >= other

    def __repr__(self):
        representation = '%s(%s' % (self.__class__.__name__, self.name)

        if self.syntax is not None:
            representation += ', %r' % self.syntax

        representation += ')'
        return representation

    def getSyntax(self):
        return self.syntax

    def setSyntax(self, v):
        self.syntax = v
        return self

    def getUnits(self):
        return self.units

    def setUnits(self, v):
        self.units = v
        return self

    def getMaxAccess(self):
        return self.maxAccess

    def setMaxAccess(self, v):
        self.maxAccess = v
        return self

    def getStatus(self):
        return self.status

    def setStatus(self, v):
        self.status = v
        return self

    def getDescription(self):
        return self.description

    def setDescription(self, v):
        self.description = v
        return self

    def getReference(self):
        return self.reference

    def setReference(self, v):
        self.reference = v
        return self

    def asn1Print(self):
        return """
OBJECT-TYPE
  SYNTAX %s
  UNITS "%s"
  MAX-ACCESS %s
  STATUS %s
  DESCRIPTION "%s"
  REFERENCE "%s" """ % (self.getSyntax().__class__.__name__,
                        self.getUnits(),
                        self.getMaxAccess(),
                        self.getStatus(),
                        self.getDescription(),
                        self.getReference())


class ManagedMibObject(ObjectType):
    """Managed MIB object.

    Implement management instrumentation access protocol which allows for
    MIB instantiation and operations on Managed Objects Instances.

    Management instrumentation protocol is typically used by SNMP Agent
    serving Managed Objects to SNMP Managers.

    The :class:`AbstractManagedMibObject` class serves as a basis
    for a handful of other classes representing various kinds of
    MIB objects. In the context of management instrumentation these
    objects are organized into a tree of the following layout:


        MibTree
           |
           +----MibScalar
           |        |
           |        +-----MibScalarInstance
           |
           +----MibTable
           |
           +----MibTableRow
                  |
                  +-------MibTableColumn
                                |
                                +------MibScalarInstance(s)

    Management instrumentation queries always come to the top of the
    tree propagating downwards.

    The basic management instrumentation operations are *read*, *readnext*
    and *write* of Managed Objects Instances. The latter covers creation
    and removal of the columnar Managed Objects Instances.
    """
    branchVersionId = 0  # changes on tree structure change
    maxAccess = 'not-accessible'

    ST_CREATE = 'create'
    ST_DESTROY = 'destroy'

    def __init__(self, name, syntax=None):
        ObjectType.__init__(self, name, syntax)
        self._vars = OidOrderedDict()

    # Subtrees registration

    def registerSubtrees(self, *subTrees):
        self.branchVersionId += 1
        for subTree in subTrees:
            if subTree.name in self._vars:
                raise error.SmiError(
                    'MIB subtree %s already registered at %s' % (subTree.name, self)
                )
            self._vars[subTree.name] = subTree

    def unregisterSubtrees(self, *names):
        self.branchVersionId += 1
        for name in names:
            # This may fail if you fill a table by exporting MibScalarInstances
            # but later drop them through SNMP.
            if name not in self._vars:
                raise error.SmiError(
                    'MIB subtree %s not registered at %s' % (name, self)
                )
            del self._vars[name]

    #
    # Tree traversal
    #
    # Missing branches are indicated by the NoSuchObjectError exception.
    # Although subtrees may indicate their missing branches by the
    # NoSuchInstanceError exception.
    #

    def getBranch(self, name, **context):
        """Return a branch of this tree where the 'name' OID may reside"""
        for keyLen in self._vars.getKeysLens():
            subName = name[:keyLen]
            if subName in self._vars:
                return self._vars[subName]

        raise error.NoSuchObjectError(name=name, idx=context.get('idx'))

    def getNextBranch(self, name, **context):
        # Start from the beginning
        if self._vars:
            first = list(self._vars.keys())[0]
        else:
            first = ()
        if self._vars and name < first:
            return self._vars[first]
        else:
            try:
                return self._vars[self._vars.nextKey(name)]
            except KeyError:
                raise error.NoSuchObjectError(name=name, idx=context.get('idx'))

    def getNode(self, name, **context):
        """Return tree node found by name"""
        if name == self.name:
            return self
        else:
            return self.getBranch(name, **context).getNode(name, **context)

    def getNextNode(self, name, **context):
        """Return tree node next to name"""
        try:
            nextNode = self.getBranch(name, **context)
        except (error.NoSuchInstanceError, error.NoSuchObjectError):
            return self.getNextBranch(name, **context)
        else:
            try:
                return nextNode.getNextNode(name, **context)
            except (error.NoSuchInstanceError, error.NoSuchObjectError):
                try:
                    return self._vars[self._vars.nextKey(nextNode.name)]
                except KeyError:
                    raise error.NoSuchObjectError(name=name, idx=context.get('idx'))

    # MIB instrumentation

    # Read operation

    def readTest(self, varBind, **context):
        """Test the ability to read Managed Object Instance.

        Implements the first of the two phases of the SNMP GET command
        processing (:RFC:`1905#section-4.2.1`).

        The goal of the first phase is to make sure that requested Managed
        Object Instance could potentially be read. When multiple Managed
        Objects Instances are read at once (likely coming all in one SNMP PDU),
        each of them has to run through the first (*test*) phase successfully
        for the system to transition to the second (*get*) phase.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            Managed Object Instance to read

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass read Managed Object Instance or an error.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains read Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: readTest(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        if name == self.name:
            cbFun((name, exval.noSuchInstance), **context)
            return

        node = exc = None

        try:
            node = self.getBranch(name, **context)

        except error.NoSuchObjectError:
            val = exval.noSuchObject

        except error.NoSuchInstanceError:
            val = exval.noSuchInstance

        except error.SmiError as exc:
            (debug.logger & debug.FLAG_INS and
             debug.logger('%s: exception %r' % (self, exc)))

        if not node:
            cbFun((name, val), **dict(context, error=exc))
            return

        node.readTest(varBind, **context)

    def readGet(self, varBind, **context):
        """Read Managed Object Instance.

        Implements the second of the two phases of the SNMP GET command
        processing (:RFC:`1905#section-4.2.1`).

        The goal of the second phase is to actually read the requested Managed
        Object Instance. When multiple Managed Objects Instances are read at
        once (likely coming all in one SNMP PDU), each of them has to run through
        the first (*test*) and second (*read) phases successfully for the whole
        read operation to succeed.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.


        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            Managed Object Instance to read

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass read Managed Object Instance or an error.

        Notes
        -----
        The callback functions (e.g. `cbFun`) has the same signature as
        this method where `varBind` contains read Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: readGet(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        if name == self.name:
            cbFun((name, exval.noSuchInstance), **context)
            return

        node = exc = None

        try:
            node = self.getBranch(name, **context)

        except error.NoSuchObjectError:
            val = exval.noSuchObject

        except error.NoSuchInstanceError:
            val = exval.noSuchInstance

        except error.SmiError as exc:
            (debug.logger & debug.FLAG_INS and
             debug.logger('%s: exception %r' % (self, exc)))

        if not node:
            cbFun((name, val), **dict(context, error=exc))
            return

        node.readGet(varBind, **context)

    def _getNextName(self, name):
        try:
            nextNode = self.getNextBranch(name)

        except (error.NoSuchInstanceError, error.NoSuchObjectError):
            return

        else:
            return nextNode.name

    depthFirst, breadthFirst = 0, 1

    def _readNext(self, meth, varBind, **context):
        name, val = varBind

        cbFun = context['cbFun']

        try:
            node = self.getBranch(name, **context)

        except (error.NoSuchInstanceError, error.NoSuchObjectError):

            node = exc = None

            try:
                node = self.getNextBranch(name, **context)

            except error.NoSuchObjectError:
                val = exval.noSuchObject

            except error.NoSuchInstanceError:
                val = exval.noSuchInstance

            except error.SmiError as exc:
                (debug.logger & debug.FLAG_INS and
                 debug.logger('%s: exception %r' % (self, exc)))

            if not node:
                nextName = context.get('nextName')
                if nextName:
                    varBind = nextName, val

                else:
                    varBind = name, exval.endOfMibView

                cbFun(varBind, **dict(context, error=exc))
                return

        nextName = self._getNextName(node.name)
        if nextName:
            context['nextName'] = nextName

        actionFun = getattr(node, meth)
        actionFun(varBind, **context)

    def readTestNext(self, varBind, **context):
        """Test the ability to read the next Managed Object Instance.

        Implements the first of the two phases of the SNMP GETNEXT command
        processing (:RFC:`1905#section-4.2.2`).

        The goal of the first phase is to make sure that requested Managed
        Object Instance could potentially be read. When multiple Managed
        Objects Instances are read at once (likely coming all in one SNMP PDU),
        each of them has to run through the first (*testnext*) phase
        successfully for the system to transition to the second (*getnext*)
        phase.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            Managed Object Instance next to which to read

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass read Managed Object Instance (the *next* one in the MIB tree
              relative to the one being requested) or an error.

            * `acFun` (callable) - user-supplied callable that is invoked to
               authorize access to the Managed Object Instance which is *next*
               to the one being requested. If not supplied, no access control
               will be performed.

        Notes
        -----
        The callback functions (e.g. `cbFun`, `acFun`) have the same signature
        as this method where `varBind` contains read Managed Object Instance
        value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: readTestNext(%s, %r)' % (self, name, val)))

        self._readNext('readTestNext', varBind, **context)

    def readGetNext(self, varBind, **context):
        """Read the next Managed Object Instance.

        Implements the second of the two phases of the SNMP GETNEXT command
        processing (:RFC:`1905#section-4.2.2`).

        The goal of the second phase is to actually read the Managed Object
        Instance which is next in the MIB tree to the one being requested.
        When multiple Managed Objects Instances are read at once (likely coming
        all in one SNMP PDU), each of them has to run through the first
        (*testnext*) and second (*getnext*) phases successfully for the whole
        read operation to succeed.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            Managed Object Instance to read

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass read Managed Object Instance (the *next* one in the MIB tree
              relative to the one being requested) or an error.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains read Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: readGetNext(%s, %r)' % (self, name, val)))

        self._readNext('readGetNext', varBind, **context)

    # Write operation

    def writeTest(self, varBind, **context):
        """Test the ability to modify Managed Object Instance.

        Implements the first of the multi-step workflow of the SNMP SET
        command processing (:RFC:`1905#section-4.2.5`).

        The goal of the first phase is to make sure that requested Managed
        Object Instance could potentially be changed. When multiple Managed
        Objects Instances are modified at once (likely coming all in one SNMP
        PDU), each of them has to run through the first (*test*) phase
        successfully for the system to transition to the second (*commit*)
        phase.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to set

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `acFun` (callable) - user-supplied callable that is invoked to
               authorize access to the requested Managed Object Instance. If
               not supplied, no access control will be performed.

        Notes
        -----
        The callback functions (e.g. `cbFun`, `acFun`) have the same signature
        as this method where `varBind` contains the new Managed Object Instance
        value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: writeTest(%s, %r)' % (self, name, val)))

        try:
            node = self.getBranch(name, **context)

        except (error.NoSuchInstanceError, error.NoSuchObjectError):
            self.createTest(varBind, **context)

        else:
            node.writeTest(varBind, **context)

    def writeCommit(self, varBind, **context):
        """Commit new value of the Managed Object Instance.

        Implements the second of the multi-step workflow of the SNMP SET
        command processing (:RFC:`1905#section-4.2.5`).

        The goal of the second phase is to actually modify the requested Managed
        Object Instance. When multiple Managed Objects Instances are modified at
        once (likely coming all in one SNMP PDU), each of them has to run through
        the second (*commit*) phase successfully for the system to transition to
        the third (*cleanup*) phase. If any single *commit* step fails, the system
        transitions into the *undo* state for each of Managed Objects Instances
        being processed at once.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to set

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains the new Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: writeCommit(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        if idx in instances[self.ST_CREATE]:
            self.createCommit(varBind, **context)
            return
 
        if idx in instances[self.ST_DESTROY]:
            self.destroyCommit(varBind, **context)
            return

        try:
            node = self.getBranch(name, **context)

        except (error.NoSuchInstanceError, error.NoSuchObjectError) as exc:
            cbFun(varBind, **dict(context, error=exc))

        else:
            node.writeCommit(varBind, **context)

    def writeCleanup(self, varBind, **context):
        """Finalize Managed Object Instance modification.

        Implements the successful third step of the multi-step workflow of the
        SNMP SET command processing (:RFC:`1905#section-4.2.5`).

        The goal of the third (successful) phase is to seal the new state of the
        requested Managed Object Instance. Once the system transition into the
        *cleanup* state, no roll back to the previous Managed Object Instance
        state is possible.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to set

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains the new Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: writeCleanup(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        self.branchVersionId += 1

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        if idx in instances[self.ST_CREATE]:
            self.createCleanup(varBind, **context)
            return

        if idx in instances[self.ST_DESTROY]:
            self.destroyCleanup(varBind, **context)
            return

        try:
            node = self.getBranch(name, **context)

        except (error.NoSuchInstanceError, error.NoSuchObjectError) as exc:
            cbFun(varBind, **dict(context, error=exc))

        else:
            node.writeCleanup(varBind, **context)

    def writeUndo(self, varBind, **context):
        """Finalize Managed Object Instance modification.

        Implements the third (unsuccessful) step of the multi-step workflow
        of the SNMP SET command processing (:RFC:`1905#section-4.2.5`).

        The goal of the third phase is to roll the Managed Object Instance
        being modified back into its previous state. The system transitions
        into the *undo* state whenever any of the simultaneously modified
        Managed Objects Instances fail on the *commit* state transitioning.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to set

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains the new Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: writeUndo(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        if idx in instances[self.ST_CREATE]:
            self.createUndo(varBind, **context)
            return

        if idx in instances[self.ST_DESTROY]:
            self.destroyUndo(varBind, **context)
            return

        try:
            node = self.getBranch(name, **context)

        except (error.NoSuchInstanceError, error.NoSuchObjectError) as exc:
            cbFun(varBind, **dict(context, error=exc))

        else:
            node.writeUndo(varBind, **context)


class MibTree(ManagedMibObject):
    """Managed MIB Tree root object.

    Represents the root node of the MIB tree implementing management
    instrumentation.

    Objects of this type can't carry any value of their own, they serve
    for holding and ordering other (children) nodes such as
    :class:`MibScalar`, :class:`MibTable`, :class:`MibTableRowcalar` objects.

    In the MIB tree, :class:`MibScalar` objects reside right under the tree
    top, each can have a single :class:`MibScalarInstance` object attached:

        MibTree
           |
           +----MibScalar
           |
           +----MibTable
           |
           +----MibTableRow
    """


class MibScalar(ManagedMibObject):
    """Managed scalar MIB object.

    Represents scalar SMI OBJECT-TYPE object implementing management
    instrumentation.

    Objects of this type can't carry any value of their own, they serve
    as structural "blueprints" for :class:`MibScalarInstance` objects.

    In the MIB tree, :class:`MibScalar` objects reside right under the tree
    top, each can have a single :class:`MibScalarInstance` object attached:

        MibTree
           |
           +----MibScalar
                    |
                    +-----MibScalarInstance
    """
    maxAccess = 'readonly'

    _suffix = (0,)

    #
    # Subtree traversal
    #
    # Missing branches are indicated by the NoSuchInstanceError exception.
    #

    def getBranch(self, name, **context):
        try:
            return ManagedMibObject.getBranch(self, name, **context)

        except (error.NoSuchInstanceError, error.NoSuchObjectError):
            raise error.NoSuchInstanceError(name=name, idx=context.get('idx'))

    def getNextBranch(self, name, **context):
        try:
            return ManagedMibObject.getNextBranch(self, name, **context)

        except (error.NoSuchInstanceError, error.NoSuchObjectError):
            raise error.NoSuchInstanceError(name=name, idx=context.get('idx'))

    def getNode(self, name, **context):
        try:
            return ManagedMibObject.getNode(self, name, **context)

        except (error.NoSuchInstanceError, error.NoSuchObjectError):
            raise error.NoSuchInstanceError(name=name, idx=context.get('idx'))

    def getNextNode(self, name, **context):
        try:
            return ManagedMibObject.getNextNode(self, name, **context)

        except (error.NoSuchInstanceError, error.NoSuchObjectError):
            raise error.NoSuchInstanceError(name=name, idx=context.get('idx'))

    # MIB instrumentation methods

    def readGet(self, varBind, **context):
        """Read Managed Object Instance.

        Implements the second of the two phases of the SNMP GET command
        processing (:RFC:`1905#section-4.2.1`).

        The goal of the second phase is to actually read the requested Managed
        Object Instance. When multiple Managed Objects Instances are read at
        once (likely coming all in one SNMP PDU), each of them has to run through
        the first (*test*) and second (*read) phases successfully for the whole
        read operation to succeed.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Beyond that, this object imposes access control logic towards the
        underlying :class:`MibScalarInstance` objects by invoking the `acFun`
        callable.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            Managed Object Instance to read

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass read Managed Object Instance or an error.

            * `acFun` (callable) - user-supplied callable that is invoked to
               authorize access to the requested Managed Object Instance. If
               not supplied, no access control will be performed.

        Notes
        -----
        The callback functions (e.g. `cbFun`, `acFun`) has the same signature as
        this method where `varBind` contains read Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: readGet(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        if name == self.name:
            cbFun((name, exval.noSuchInstance), **context)
            return

        acFun = context.get('acFun')
        if acFun:
            if (self.maxAccess not in ('readonly', 'readwrite', 'readcreate') or
                    acFun('read', (name, self.syntax), **context)):
                cbFun((name, exval.noSuchInstance), **context)
                return

        ManagedMibObject.readGet(self, varBind, **context)

    def readGetNext(self, varBind, **context):
        """Read the next Managed Object Instance.

        Implements the second of the two phases of the SNMP GETNEXT command
        processing (:RFC:`1905#section-4.2.2`).

        The goal of the second phase is to actually read the Managed Object
        Instance which is next in the MIB tree to the one being requested.
        When multiple Managed Objects Instances are read at once (likely coming
        all in one SNMP PDU), each of them has to run through the first
        (*testnext*) and second (*getnext*) phases successfully for the whole
        read operation to succeed.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Beyond that, this object imposes access control logic towards the
        underlying :class:`MibScalarInstance` objects by invoking the `acFun`
        callable.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            Managed Object Instance to read

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass read Managed Object Instance (the *next* one in the MIB tree
              relative to the one being requested) or an error.

            * `acFun` (callable) - user-supplied callable that is invoked to
               authorize access to the Managed Object Instance which is *next*
               to the one being requested. If not supplied, no access control
               will be performed.

        Notes
        -----
        The callback functions (e.g. `cbFun`, `acFun`) have the same signature
        as this method where `varBind` contains read Managed Object Instance
        value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: readGetNext(%s, %r)' % (self, name, val)))

        acFun = context.get('acFun')
        if acFun:
            if (self.maxAccess not in ('readonly', 'readwrite', 'readcreate') or
                    acFun('read', (name, self.syntax), **context)):
                nextName = context.get('nextName')
                if nextName:
                    varBind = nextName, exval.noSuchInstance
                else:
                    varBind = name, exval.endOfMibView

                cbFun = context['cbFun']
                cbFun(varBind, **context)
                return

        ManagedMibObject.readGetNext(self, varBind, **context)

    def writeTest(self, varBind, **context):
        """Test the ability to modify Managed Object Instance.

        Implements the first of the multi-step workflow of the SNMP SET
        command processing (:RFC:`1905#section-4.2.5`).

        The goal of the first phase is to make sure that requested Managed
        Object Instance could potentially be changed. When multiple Managed
        Objects Instances are modified at once (likely coming all in one SNMP
        PDU), each of them has to run through the first (*test*) phase
        successfully for the system to transition to the second (*commit*)
        phase.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Beyond that, this object imposes access control logic towards the
        underlying :class:`MibScalarInstance` objects by invoking the `acFun`
        callable.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to set

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `acFun` (callable) - user-supplied callable that is invoked to
               authorize access to the requested Managed Object Instance. If
               not supplied, no access control will be performed.

        Notes
        -----
        The callback functions (e.g. `cbFun`, `acFun`) have the same signature
        as this method where `varBind` contains the new Managed Object Instance
        value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: writeTest(%s, %r)' % (self, name, val)))

        acFun = context.get('acFun')
        if acFun:
            if (self.maxAccess not in ('readwrite', 'readcreate') or
                    acFun('write', (name, self.syntax), **context)):
                exc = error.NotWritableError(name=name, idx=context.get('idx'))
                cbFun = context['cbFun']
                cbFun(varBind, **dict(context, error=exc))
                return

        ManagedMibObject.writeTest(self, varBind, **context)

    def _checkSuffix(self, name):
        suffix = name[:len(self.name)]
        return suffix == (0,)

    def createTest(self, varBind, **context):
        """Test the ability to create a Managed Object Instance.

        Implements the first of the multi-step workflow similar to the SNMP SET
        command processing (:RFC:`1905#section-4.2.5`).

        The goal of the first phase is to make sure that requested Managed
        Object Instance could potentially be created. When multiple Managed
        Objects Instances are modified at once (likely coming all in one SNMP
        PDU), each of them has to run through the first (*test*) phase
        successfully for the system to transition to the second (*commit*)
        phase.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to create

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable): user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `instances` (dict): user-supplied dict for temporarily holding
              Managed Objects Instances being created.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this method
        where `varBind` contains the new Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: createTest(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        if not self._checkSuffix(name):
            exc = error.NoCreationError(name=name, idx=context.get('idx'))
            cbFun(varBind, **dict(context, error=exc))
            return

        acFun = context.get('acFun')
        if acFun:
            if self.maxAccess != 'readcreate' or acFun('write', varBind, **context):
                debug.logger & debug.FLAG_ACL and debug.logger(
                    'createTest: %s=%r %s at %s' % (name, val, self.maxAccess, self.name))
                exc = error.NoCreationError(name=name, idx=context.get('idx'))
                cbFun(varBind, **dict(context, error=exc))
                return

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        instId = name[len(self.name):]

        if name in self._vars:
            cbFun(varBind, **context)
            return

        instances[self.ST_CREATE][idx] = MibScalarInstance(self.name, instId, self.syntax.clone())

        instances[self.ST_CREATE][idx].writeTest((name, val), **context)

    def createCommit(self, varBind, **context):
        """Create Managed Object Instance.

        Implements the second of the multi-step workflow similar to the SNMP SET
        command processing (:RFC:`1905#section-4.2.5`).

        The goal of the second phase is to actually create requested Managed
        Object Instance. When multiple Managed Objects Instances are created/modified
        at once (likely coming all in one SNMP PDU), each of them has to run through
        the second (*commit*) phase successfully for the system to transition to
        the third (*cleanup*) phase. If any single *commit* step fails, the system
        transitions into the *undo* state for each of Managed Objects Instances
        being processed at once.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to create

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `instances` (dict): user-supplied dict for temporarily holding
              Managed Objects Instances being created.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains the new Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: writeCommit(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        if name in self._vars:
            cbFun(varBind, **context)
            return

        # NOTE: multiple names are possible in a single PDU, that could collide
        # Therefore let's keep old object indexed by (negative) var-bind index
        self._vars[name], instances[self.ST_CREATE][-idx - 1] = instances[self.ST_CREATE][idx], self._vars.get(name)

        instances[self.ST_CREATE][idx].writeCommit(varBind, **context)

    def createCleanup(self, varBind, **context):
        """Finalize Managed Object Instance creation.

        Implements the successful third step of the multi-step workflow similar to
        the SNMP SET command processing (:RFC:`1905#section-4.2.5`).

        The goal of the third (successful) phase is to seal the new Managed Object
        Instance. Once the system transitions into the *cleanup* state, no roll back
        to the previous Managed Object Instance state is possible.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to create

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `instances` (dict): user-supplied dict for temporarily holding
              Managed Objects Instances being created.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains the new Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: createCleanup(%s, %r)' % (self, name, val)))

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        self.branchVersionId += 1

        instances[self.ST_CREATE].pop(-idx - 1, None)

        self._vars[name].writeCleanup(varBind, **context)

    def createUndo(self, varBind, **context):
        """Undo Managed Object Instance creation.

        Implements the third (unsuccessful) step of the multi-step workflow
        similar to the SNMP SET command processing (:RFC:`1905#section-4.2.5`).

        The goal of the third phase is to delete the Managed Object Instance
        being created. The system transitions into the *undo* state whenever
        any of the simultaneously modified Managed Objects Instances fail on the
        *commit* state transitioning.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to create

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `instances` (dict): user-supplied dict for temporarily holding
              Managed Objects Instances being created.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains the new Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: createUndo(%s, %r)' % (self, name, val)))

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        instances[self.ST_CREATE].pop(-idx - 1, None)

        obj = self._vars.pop(name, None)
        if obj:
            obj.writeUndo(varBind, **context)

        else:
            cbFun = context['cbFun']
            cbFun(varBind, **context)


class MibScalarInstance(ManagedMibObject):
    """Managed scalar instance MIB object.

    Represents an instance of a scalar SMI OBJECT-TYPE object implementing
    management instrumentation.

    Objects of this type carry the actual value or somehow interface the
    data source.

    In the MIB tree, :class:`MibScalarInstance` objects reside right under their
    :class:`MibScalarInstance` parent object:

        MibTree
           |
           +----MibScalar
                    |
                    +-----MibScalarInstance
    """
    def __init__(self, typeName, instId, syntax):
        ManagedMibObject.__init__(self, typeName + instId, syntax)
        self.typeName = typeName
        self.instId = instId

    #
    # Managed object value access methods
    #

    def getValue(self, name, **context):
        debug.logger & debug.FLAG_INS and debug.logger('getValue: returning %r for %s' % (self.syntax, self.name))
        return self.syntax.clone()

    def setValue(self, value, name, **context):
        if value is None:
            value = univ.noValue

        try:
            if hasattr(self.syntax, 'setValue'):
                return self.syntax.setValue(value)
            else:
                return self.syntax.clone(value)

        except PyAsn1Error as exc:
            debug.logger & debug.FLAG_INS and debug.logger('setValue: %s=%r failed with traceback %s' % (
                self.name, value, traceback.format_exception(*sys.exc_info())))
            if isinstance(exc, error.TableRowManagement):
                raise exc
            else:
                raise error.WrongValueError(name=name, idx=context.get('idx'), msg=exc)

    #
    # Subtree traversal
    #
    # Missing branches are indicated by the NoSuchInstanceError exception.
    #

    def getBranch(self, name, **context):
        try:
            return ManagedMibObject.getBranch(self, name, **context)

        except (error.NoSuchInstanceError, error.NoSuchObjectError):
            raise error.NoSuchInstanceError(name=name, idx=context.get('idx'))

    def getNextBranch(self, name, **context):
        try:
            return ManagedMibObject.getNextBranch(self, name, **context)

        except (error.NoSuchInstanceError, error.NoSuchObjectError):
            raise error.NoSuchInstanceError(name=name, idx=context.get('idx'))

    def getNode(self, name, **context):
        # Recursion terminator
        if name == self.name:
            return self
        raise error.NoSuchInstanceError(name=name, idx=context.get('idx'))

    def getNextNode(self, name, **context):
        raise error.NoSuchInstanceError(name=name, idx=context.get('idx'))

    # MIB instrumentation methods

    def readTest(self, varBind, **context):
        """Test the ability to read Managed Object Instance.

        Implements the first of the two phases of the SNMP GET command
        processing (:RFC:`1905#section-4.2.1`).

        The goal of the first phase is to make sure that requested Managed
        Object Instance could potentially be read. When multiple Managed
        Objects Instances are read at once (likely coming all in one SNMP PDU),
        each of them has to run through the first (*test*) phase successfully
        for the system to transition to the second (*get*) phase.

        The role of this object in the MIB tree is terminal. It does access the
        actual Managed Object Instance.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            Managed Object Instance to read

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass read Managed Object Instance or an error.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains read Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: readTest(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        if name != self.name or not self.syntax.isValue:
            exc = error.NoSuchInstanceError(name=name, idx=context.get('idx'))
            cbFun(varBind, **dict(context, error=exc))
            return

        cbFun((self.name, self.syntax), **context)

    def readGet(self, varBind, **context):
        """Read Managed Object Instance.

        Implements the second of the two phases of the SNMP GET command
        processing (:RFC:`1905#section-4.2.1`).

        The goal of the second phase is to actually read the requested Managed
        Object Instance. When multiple Managed Objects Instances are read at
        once (likely coming all in one SNMP PDU), each of them has to run through
        the first (*test*) and second (*read) phases successfully for the whole
        read operation to succeed.

        The role of this object in the MIB tree is terminal. It does access the
        actual Managed Object Instance.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            Managed Object Instance to read

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass read Managed Object Instance or an error.

        Notes
        -----
        The callback functions (e.g. `cbFun`) has the same signature as
        this method where `varBind` contains read Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: readGet(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        if name != self.name or not self.syntax.isValue:
            exc = error.NoSuchInstanceError(name=name, idx=context.get('idx'))
            cbFun(varBind, **dict(context, error=exc))
            return

        cbFun((self.name, self.getValue(name, **context)), **context)

    def readTestNext(self, varBind, **context):
        """Test the ability to read the next Managed Object Instance.

        Implements the first of the two phases of the SNMP GETNEXT command
        processing (:RFC:`1905#section-4.2.2`).

        The goal of the first phase is to make sure that requested Managed
        Object Instance could potentially be read. When multiple Managed
        Objects Instances are read at once (likely coming all in one SNMP PDU),
        each of them has to run through the first (*testnext*) phase
        successfully for the system to transition to the second (*getnext*)
        phase.

        The role of this object in the MIB tree is terminal. It does access the
        actual Managed Object Instance.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            Managed Object Instance next to which to read

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass read Managed Object Instance (the *next* one in the MIB tree
              relative to the one being requested) or an error.

            * `acFun` (callable) - user-supplied callable that is invoked to
               authorize access to the Managed Object Instance which is *next*
               to the one being requested. If not supplied, no access control
               will be performed.

        Notes
        -----
        The callback functions (e.g. `cbFun`, `acFun`) have the same signature
        as this method where `varBind` contains read Managed Object Instance
        value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: readTestNext(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        if name >= self.name or not self.syntax.isValue:
            nextName = context.get('nextName')
            if nextName:
                varBind = nextName, exval.noSuchInstance
            else:
                varBind = name, exval.endOfMibView

            cbFun(varBind, **context)
            return

        cbFun((self.name, self.syntax), **context)

    def readGetNext(self, varBind, **context):
        """Read the next Managed Object Instance.

        Implements the second of the two phases of the SNMP GETNEXT command
        processing (:RFC:`1905#section-4.2.2`).

        The goal of the second phase is to actually read the Managed Object
        Instance which is next in the MIB tree to the one being requested.
        When multiple Managed Objects Instances are read at once (likely coming
        all in one SNMP PDU), each of them has to run through the first
        (*testnext*) and second (*getnext*) phases successfully for the whole
        read operation to succeed.

        The role of this object in the MIB tree is terminal. It does access the
        actual Managed Object Instance.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            Managed Object Instance to read

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass read Managed Object Instance (the *next* one in the MIB tree
              relative to the one being requested) or an error.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains read Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: readGetNext(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        if name >= self.name or not self.syntax.isValue:
            nextName = context.get('nextName')
            if nextName:
                varBind = nextName, exval.noSuchInstance
            else:
                varBind = name, exval.endOfMibView

            cbFun(varBind, **context)
            return

        cbFun((self.name, self.getValue(self.name, **context)), **context)

    def writeTest(self, varBind, **context):
        """Test the ability to modify Managed Object Instance.

        Implements the first of the multi-step workflow of the SNMP SET
        command processing (:RFC:`1905#section-4.2.5`).

        The goal of the first phase is to make sure that requested Managed
        Object Instance could potentially be changed. When multiple Managed
        Objects Instances are modified at once (likely coming all in one SNMP
        PDU), each of them has to run through the first (*test*) phase
        successfully for the system to transition to the second (*commit*)
        phase.

        The role of this object in the MIB tree is terminal. It does access the
        actual Managed Object Instance.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to set

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `acFun` (callable) - user-supplied callable that is invoked to
               authorize access to the requested Managed Object Instance. If
               not supplied, no access control will be performed.

            * `instances` (dict): user-supplied dict for temporarily holding
              the values of the Managed Objects Instances being modified.

        Notes
        -----
        The callback functions (e.g. `cbFun`, `acFun`) have the same signature
        as this method where `varBind` contains the new Managed Object Instance
        value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: writeTest(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        if name != self.name:
            exc = error.NoSuchInstanceError(name=name, idx=context.get('idx'))
            cbFun(varBind, **dict(context, error=exc))

        # Make sure write's allowed
        try:
            instances[self.ST_CREATE][idx] = self.setValue(val, name, **context)

        except error.MibOperationError as exc:
            # SMI exceptions may carry additional content
            if 'syntax' in exc:
                instances[self.ST_CREATE][idx] = exc['syntax']
                cbFun(varBind, **dict(context, error=exc))
                return

            else:
                exc = error.WrongValueError(name=name, idx=context.get('idx'), msg=exc)
                cbFun(varBind, **dict(context, error=exc))
                return

        cbFun((self.name, self.syntax), **context)

    def writeCommit(self, varBind, **context):
        """Commit new value of the Managed Object Instance.

        Implements the second of the multi-step workflow of the SNMP SET
        command processing (:RFC:`1905#section-4.2.5`).

        The goal of the second phase is to actually modify the requested Managed
        Object Instance. When multiple Managed Objects Instances are modified at
        once (likely coming all in one SNMP PDU), each of them has to run through
        the second (*commit*) phase successfully for the system to transition to
        the third (*cleanup*) phase. If any single *commit* step fails, the system
        transitions into the *undo* state for each of Managed Objects Instances
        being processed at once.

        The role of this object in the MIB tree is terminal. It does access the
        actual Managed Object Instance.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to set

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `instances` (dict): user-supplied dict for temporarily holding
              the values of the Managed Objects Instances being modified.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains the new Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: writeCommit(%s, %r)' % (self, name, val)))

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        instances[self.ST_CREATE][-idx - 1], self.syntax = self.syntax, instances[self.ST_CREATE][idx]

        cbFun = context['cbFun']
        cbFun((self.name, self.syntax), **context)

    def writeCleanup(self, varBind, **context):
        """Finalize Managed Object Instance modification.

        Implements the successful third step of the multi-step workflow of the
        SNMP SET command processing (:RFC:`1905#section-4.2.5`).

        The goal of the third (successful) phase is to seal the new state of the
        requested Managed Object Instance. Once the system transition into the
        *cleanup* state, no roll back to the previous Managed Object Instance
        state is possible.

        The role of this object in the MIB tree is terminal. It does access the
        actual Managed Object Instance.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to set

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `instances` (dict): user-supplied dict for temporarily holding
              the values of the Managed Objects Instances being modified.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains the new Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: writeCleanup(%s, %r)' % (self, name, val)))

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        self.branchVersionId += 1

        instances[self.ST_CREATE].pop(idx, None)
        instances[self.ST_CREATE].pop(-idx - 1, None)

        cbFun = context['cbFun']
        cbFun((self.name, self.syntax), **context)

    def writeUndo(self, varBind, **context):
        """Undo Managed Object Instance modification.

        Implements the third (unsuccessful) step of the multi-step workflow
        of the SNMP SET command processing (:RFC:`1905#section-4.2.5`).

        The goal of the third phase is to roll the Managed Object Instance
        being modified back into its previous state. The system transitions
        into the *undo* state whenever any of the simultaneously modified
        Managed Objects Instances fail on the *commit* state transitioning.

        The role of this object in the MIB tree is terminal. It does access the
        actual Managed Object Instance.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to set

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `instances` (dict): user-supplied dict for temporarily holding
              the values of the Managed Objects Instances being modified.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains the new Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: writeUndo(%s, %r)' % (self, name, val)))

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        self.syntax = instances[self.ST_CREATE].pop(-idx - 1, None)
        instances[self.ST_CREATE].pop(idx, None)

        cbFun = context['cbFun']
        cbFun((self.name, self.syntax), **context)


# Conceptual table classes

class MibTableColumn(MibScalar, ObjectType):
    """Managed columnar instance MIB object.

    Represents columnar object (`OBJECT-TYPE`) of the SMI table implementing
    management instrumentation.

    Objects of this type do not carry the actual value, but can create or
    destroy underlying :class:`MibScalarInstance` objects.

    In the MIB tree, :class:`MibTableColumn` objects reside right under their
    :class:`MibTableRow` parent object, each :class:`MibTableColumn` can have
    zero or more children :class:`MibScalarInstance` objects representing SNMP
    table cells:

        MibTree
           |
           +----MibTableRow
                     |
                     +-------MibTableColumn
                                   |
                                   +------MibScalarInstance
                                   +------MibScalarInstance
                                   ...
    """

    #
    # Subtree traversal
    #
    # Missing leaves are indicated by the NoSuchInstanceError exception.
    #

    def getBranch(self, name, **context):
        if name in self._vars:
            return self._vars[name]
        raise error.NoSuchInstanceError(name=name, idx=context.get('idx'))

    # Column creation (this should probably be converted into some state
    # machine for clarity). Also, it might be a good idea to indicate
    # defaulted cols creation in a clearer way than just a val == None.

    def _checkSuffix(self, name):
        # NOTE: we could have verified the index validity
        return name[:len(self.name)]

    # Column destruction

    def destroyTest(self, varBind, **context):
        """Test the ability to destroy a Managed Object Instance.

        Implements the first of the multi-step workflow similar to SNMP SET
        command processing (:RFC:`1905#section-4.2.5`).

        The goal of the first phase is to make sure that requested Managed
        Object Instance could potentially be destroyed. When multiple Managed
        Objects Instances are modified at once (likely coming all in one SNMP
        PDU), each of them has to run through the first (*test*) phase
        successfully for the system to transition to the second (*commit*)
        phase.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to destroy

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable): user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `instances` (dict): user-supplied dict for temporarily holding
              Managed Objects Instances being destroyed.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this method
        where `varBind` contains the new Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: destroyTest(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        if not self._checkSuffix(name):
            exc = error.NotWritableError(name=name, idx=context.get('idx'))
            cbFun(varBind, **dict(context, error=exc))
            return

        acFun = context.get('acFun')
        if acFun:
            if self.maxAccess != 'readcreate' or acFun('write', varBind, **context):
                debug.logger & debug.FLAG_ACL and debug.logger(
                    'destroyTest: %s=%r %s at %s' % (name, val, self.maxAccess, self.name))
                exc = error.NotWritableError(name=name, idx=context.get('idx'))
                cbFun(varBind, **dict(context, error=exc))
                return

        try:
            instances[self.ST_DESTROY][idx] = instances[self.ST_CREATE].pop(idx)

        except KeyError:
            pass

        else:
            (debug.logger & debug.FLAG_INS and
             debug.logger('%s: terminated columnar instance %s creation' % (self, name)))

        cbFun(varBind, **context)

    def destroyCommit(self, varBind, **context):
        """Destroy Managed Object Instance.

        Implements the second of the multi-step workflow similar to the SNMP SET
        command processing (:RFC:`1905#section-4.2.5`).

        The goal of the second phase is to actually remove requested Managed
        Object Instance from the MIB tree. When multiple Managed Objects Instances
        are destroyed/modified at once (likely coming all in one SNMP PDU), each
        of them has to run through the second (*commit*) phase successfully for
        the system to transition to the third (*cleanup*) phase. If any single
        *commit* step fails, the system transitions into the *undo* state for
        each of Managed Objects Instances being processed at once.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to destroy

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `instances` (dict): user-supplied dict for temporarily holding
              Managed Objects Instances being destroyed.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains the new Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: destroyCommit(%s, %r)' % (self, name, val)))

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        # NOTE: multiple names are possible in a single PDU, that could collide
        # Therefore let's keep old object indexed by (negative) var-bind index
        try:
            instances[self.ST_DESTROY][-idx - 1] = self._vars.pop(name)

        except KeyError:
            pass

        cbFun = context['cbFun']
        cbFun(varBind, **context)

    def destroyCleanup(self, varBind, **context):
        """Finalize Managed Object Instance destruction.

        Implements the successful third step of the multi-step workflow similar to
        the SNMP SET command processing (:RFC:`1905#section-4.2.5`).

        The goal of the third (successful) phase is to finalize the destruction
        of the Managed Object Instance. Once the system transitions into the
        *cleanup* state, no roll back to the previous Managed Object Instance
        state is possible.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to destroy

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `instances` (dict): user-supplied dict for temporarily holding
              Managed Objects Instances being destroyed.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains the new Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: destroyCleanup(%s, %r)' % (self, name, val)))

        self.branchVersionId += 1

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        instances[self.ST_DESTROY].pop(idx, None)
        instances[self.ST_DESTROY].pop(-idx - 1, None)

        cbFun = context['cbFun']
        cbFun(varBind, **context)

    def destroyUndo(self, varBind, **context):
        """Undo Managed Object Instance destruction.

        Implements the third (unsuccessful) step of the multi-step workflow
        similar to the SNMP SET command processing (:RFC:`1905#section-4.2.5`).

        The goal of the third phase is to revive the Managed Object Instance
        being destroyed. The system transitions into the *undo* state whenever
        any of the simultaneously modified Managed Objects Instances fail on the
        *commit* state transitioning.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to destroy

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `instances` (dict): user-supplied dict for temporarily holding
              Managed Objects Instances being destroyed.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains the new Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: destroyUndo(%s, %r)' % (self, name, val)))

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        try:
            self._vars[name] = instances[self.ST_DESTROY].pop(-idx - 1)

        except KeyError:
            self._vars.pop(name, None)

        instances[self.ST_DESTROY].pop(idx, None)

        cbFun = context['cbFun']
        cbFun(varBind, **context)


class MibTableRow(ManagedMibObject):
    """Managed table row MIB object.

    Represents SMI table row object (`OBJECT-TYPE`) implementing
    management instrumentation.

    Objects of this type can't carry any value of their own, their major
    role is to ensure table row consistency by catching and propagating
    columnar events (such as column creation or destruction coming from
    :class:`RowStatus` via :class:`MibTableColumn`) across the whole row.

    In the MIB tree, :class:`MibTableRow` objects reside right under the tree
    top, each can have one or more :class:`MibTableColumn` objects attached:

        MibTree
           |
           +----MibTableRow
                    |
                    +-----MibTableColumn
    """

    def __init__(self, name):
        ManagedMibObject.__init__(self, name)
        self._idToIdxCache = cache.Cache()
        self._idxToIdCache = cache.Cache()
        self._indexNames = ()
        self._augmentingRows = set()

    # Table indices resolution. Handle almost all possible rfc1902 types
    # explicitly rather than by means of isSuperTypeOf() method because
    # some subtypes may be implicitly tagged what renders base tag
    # unavailable.

    def oidToValue(self, syntax, identifier, impliedFlag=False, parentIndices=None):
        """Turn SMI table instance identifier into a value object.

        SNMP SMI table objects are identified by OIDs composed of columnar
        object ID and instance index. The index part can be composed
        from the values of one or more tabular objects.

        This method takes sequence of integers, representing the tail piece
        of a tabular object identifier, and turns it into a value object.

        Parameters
        ----------
        syntax: :py:class:`Integer`, :py:class:`OctetString`, :py:class:`ObjectIdentifier`, :py:class:`IpAddress` or :py:class:`Bits` -
            one of the SNMP data types that can be used in SMI table indices.

        identifier: :py:class:`tuple` - tuple of integers representing the tail
            piece of an OBJECT IDENTIFIER (i.e. tabular object instance ID)

        impliedFlag: :py:class:`bool` - if `False`, the length of the
            serialized value is expected to be present as the first integer of
            the sequence. Otherwise the length is not included (which is
            frequently the case for the last index in the series or a
            fixed-length value).

        Returns
        -------
        :py:class:`object` - Initialized instance of `syntax`
        """
        if not identifier:
            raise error.SmiError('Short OID for index %r' % (syntax,))

        if hasattr(syntax, 'cloneFromName'):
            return syntax.cloneFromName(
                identifier, impliedFlag, parentRow=self, parentIndices=parentIndices)

        baseTag = syntax.getTagSet().getBaseTag()
        if baseTag == Integer.tagSet.getBaseTag():
            return syntax.clone(identifier[0]), identifier[1:]

        elif IpAddress.tagSet.isSuperTagSetOf(syntax.getTagSet()):
            return syntax.clone(
                '.'.join([str(x) for x in identifier[:4]])), identifier[4:]

        elif baseTag == OctetString.tagSet.getBaseTag():
            # rfc1902, 7.7
            if impliedFlag:
                return syntax.clone(tuple(identifier)), ()

            elif syntax.isFixedLength():
                l = syntax.getFixedLength()
                return syntax.clone(tuple(identifier[:l])), identifier[l:]

            else:
                return syntax.clone(
                    tuple(identifier[1:identifier[0] + 1])), identifier[identifier[0] + 1:]

        elif baseTag == ObjectIdentifier.tagSet.getBaseTag():
            if impliedFlag:
                return syntax.clone(identifier), ()

            else:
                return syntax.clone(
                    identifier[1:identifier[0] + 1]), identifier[identifier[0] + 1:]

        # rfc2578, 7.1
        elif baseTag == Bits.tagSet.getBaseTag():
            return syntax.clone(
                tuple(identifier[1:identifier[0] + 1])), identifier[identifier[0] + 1:]

        else:
            raise error.SmiError('Unknown value type for index %r' % (syntax,))

    setFromName = oidToValue

    def valueToOid(self, value, impliedFlag=False, parentIndices=None):
        """Turn value object into SMI table instance identifier.

        SNMP SMI table objects are identified by OIDs composed of columnar
        object ID and instance index. The index part can be composed
        from the values of one or more tabular objects.

        This method takes an arbitrary value object and turns it into a
        sequence of integers representing the tail piece of a tabular
        object identifier.

        Parameters
        ----------
        value: one of the SNMP data types that can be used in SMI table
            indices. Allowed types are: :py:class:`Integer`,
            :py:class:`OctetString`, :py:class:`ObjectIdentifier`,
            :py:class:`IpAddress` and :py:class:`Bits`.

        impliedFlag: :py:class:`bool` - if `False`, the length of the
            serialized value is included as the first integer of the sequence.
            Otherwise the length is not included (which is frequently the
            case for the last index in the series or a fixed-length value).

        Returns
        -------
        :py:class:`tuple` - tuple of integers representing the tail piece
            of an OBJECT IDENTIFIER (i.e. tabular object instance ID)
        """
        if hasattr(value, 'cloneAsName'):
            return value.cloneAsName(impliedFlag, parentRow=self, parentIndices=parentIndices)

        baseTag = value.getTagSet().getBaseTag()
        if baseTag == Integer.tagSet.getBaseTag():
            return int(value),

        elif IpAddress.tagSet.isSuperTagSetOf(value.getTagSet()):
            return value.asNumbers()

        elif baseTag == OctetString.tagSet.getBaseTag():
            if impliedFlag or value.isFixedLength():
                initial = ()
            else:
                initial = (len(value),)
            return initial + value.asNumbers()

        elif baseTag == ObjectIdentifier.tagSet.getBaseTag():
            if impliedFlag:
                return tuple(value)
            else:
                return (len(value),) + tuple(value)

        # rfc2578, 7.1
        elif baseTag == Bits.tagSet.getBaseTag():
            return (len(value),) + value.asNumbers()

        else:
            raise error.SmiError('Unknown value type for index %r' % (value,))

    getAsName = valueToOid

    def announceManagementEvent(self, action, varBind, **context):
        """Announce mass operation on parent table's row.

        SNMP SMI provides a way to extend already existing SMI table with
        another table. Whenever a mass operation on parent table's column
        is performed (e.g. row creation or destruction), this operation
        has to be propagated over all the extending tables.

        This method gets invoked on parent :py:class:`MibTableRow` whenever
        row modification is performed on the parent table.

        Parameters
        ----------
        action: :py:class:`str` any of :py:class:`MibInstrumController`'s states
            being applied on the parent table's row.

        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new :py:class:`RowStatus`  Managed Object Instance value being set
            on parent table row

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked once
                all the consumers of this notifications finished with their stuff
                or an error occurs

        Notes
        -----
        The callback functions (e.g. `cbFun`) expects two parameters: `varBind`
        and `**context`.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        cbFun = context['cbFun']

        if not self._augmentingRows:
            cbFun(varBind, **context)
            return

        # Convert OID suffix into index values
        instId = name[len(self.name) + 1:]
        baseIndices = []
        indices = []
        for impliedFlag, modName, symName in self._indexNames:
            mibObj, = mibBuilder.importSymbols(modName, symName)
            syntax, instId = self.oidToValue(mibObj.syntax, instId,
                                             impliedFlag, indices)

            if self.name == mibObj.name[:-1]:
                baseIndices.append((mibObj.name, syntax))

            indices.append(syntax)

        if instId:
            exc = error.SmiError('Excessive instance identifier sub-OIDs left at %s: %s' % (self, instId))
            cbFun(varBind, **dict(context, error=exc))
            return

        if not baseIndices:
            cbFun(varBind, **context)
            return

        count = [len(self._augmentingRows)]

        def _cbFun(varBind, **context):
            count[0] -= 1

            if not count[0]:
                cbFun(varBind, **context)

        for modName, mibSym in self._augmentingRows:
            mibObj, = mibBuilder.importSymbols(modName, mibSym)
            mibObj.receiveManagementEvent(action, (baseIndices, val), **dict(context, cbFun=_cbFun))

            debug.logger & debug.FLAG_INS and debug.logger('announceManagementEvent %s to %s' % (action, mibObj))

    def receiveManagementEvent(self, action, varBind, **context):
        """Apply mass operation on extending table's row.

        SNMP SMI provides a way to extend already existing SMI table with
        another table. Whenever a mass operation on parent table's column
        is performed (e.g. row creation or destruction), this operation
        has to be propagated over all the extending tables.

        This method gets invoked on the extending :py:class:`MibTableRow`
        object whenever row modification is performed on the parent table.

        Parameters
        ----------
        action: :py:class:`str` any of :py:class:`MibInstrumController`'s states
            to apply on extending table's row.

        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new :py:class:`RowStatus`  Managed Object Instance value being set
            on parent table row

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked once
                the requested operation has been applied on all columns of the
                extending table or an error occurs

        Notes
        -----
        The callback functions (e.g. `cbFun`) expects two parameters: `varBind`
        and `**context`.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        baseIndices, val = varBind

        # The default implementation supports one-to-one rows dependency
        instId = ()

        # Resolve indices intersection
        for impliedFlag, modName, symName in self._indexNames:
            mibObj, = mibBuilder.importSymbols(modName, symName)
            parentIndices = []
            for name, syntax in baseIndices:
                if name == mibObj.name:
                    instId += self.valueToOid(syntax, impliedFlag, parentIndices)
                parentIndices.append(syntax)

        if instId:
            debug.logger & debug.FLAG_INS and debug.logger(
                'receiveManagementEvent %s for suffix %s' % (action, instId))

            self._manageColumns(action, (self.name + (0,) + instId, val), **context)

    def registerAugmentation(self, *names):
        """Register table extension.

        SNMP SMI provides a way to extend already existing SMI table with
        another table. This method registers dependent (extending) table
        (or type :py:class:`MibTableRow`) to already existing table.

        Whenever a row of the parent table is created or destroyed, the
        same mass columnar operation is applied on the extending table
        row.

        Parameters
        ----------
        names: :py:class:`tuple`
            One or more `tuple`'s of `str` referring to the extending table by
            MIB module name (first `str`) and `:py:class:`MibTableRow` object
            name (second `str`).
        """
        for name in names:
            if name in self._augmentingRows:
                raise error.SmiError(
                    'Row %s already augmented by %s::%s' % (self.name, name[0], name[1])
                )

            self._augmentingRows.add(name)

        return self

    registerAugmentions = registerAugmentation

    def setIndexNames(self, *names):
        for name in names:
            self._indexNames += (name,)
        return self

    def getIndexNames(self):
        return self._indexNames

    def _manageColumns(self, action, varBind, **context):
        """Apply a management action on all columns

        Parameters
        ----------
        action: :py:class:`str` any of :py:class:`MibInstrumController`'s states
            to apply on all columns but the one passed in `varBind`

        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new :py:class:`RowStatus`  Managed Object Instance value being set
            on table row

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked once
              all columns have been processed or an error occurs

        Notes
        -----
        The callback functions (e.g. `cbFun`) expects two parameters: `varBind`
        and `**context`.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.

        Assumes that row consistency check has been triggered by RowStatus
        columnar object transition into `active` state.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: _manageColumns(%s, %s, %r)' % (self, action, name, val)))

        cbFun = context['cbFun']

        colLen = len(self.name) + 1

        # Build a map of index names and values for automatic initialization
        indexVals = {}

        instId = name[colLen:]
        indices = []

        for impliedFlag, modName, symName in self._indexNames:
            mibObj, = mibBuilder.importSymbols(modName, symName)
            syntax, instId = self.oidToValue(mibObj.syntax, instId, impliedFlag, indices)
            indexVals[mibObj.name] = syntax
            indices.append(syntax)

        count = [len(self._vars)]

        if name[:colLen] in self._vars:
            count[0] -= 1

        def _cbFun(varBind, **context):
            count[0] -= 1

            if not count[0]:
                cbFun(varBind, **context)

        for colName, colObj in self._vars.items():
            acFun = context.get('acFun')

            if colName in indexVals:
                colInstanceValue = indexVals[colName]
                # Index column is usually read-only
                acFun = None

            elif name[:colLen] == colName:
                # status column is following `write` path
                continue

            else:
                colInstanceValue = None

            actionFun = getattr(colObj, action)

            colInstanceName = colName + name[colLen:]

            actionFun((colInstanceName, colInstanceValue),
                      **dict(context, acFun=acFun, cbFun=_cbFun))

            debug.logger & debug.FLAG_INS and debug.logger(
                '_manageColumns: action %s name %s instance %s %svalue %r' % (
                    action, name, instId, name in indexVals and "index " or "", indexVals.get(name, val)))

    def _checkColumns(self, varBind, **context):
        """Check the consistency of all columns.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new :py:class:`RowStatus`  Managed Object Instance value being set
            on table row

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains the new Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.

        Assume that row consistency check has been triggered by RowStatus
        columnar object transition into `active` state.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: _checkColumns(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        # RowStatus != active
        if val != 1:
            cbFun(varBind, **context)
            return

        count = [len(self._vars)]

        def _cbFun(varBind, **context):
            count[0] -= 1

            name, val = varBind

            if count[0] >= 0:
                exc = context.get('error')
                if exc or not val.hasValue():
                    count[0] = -1  # ignore the rest of callbacks
                    exc = error.InconsistentValueError(msg='Inconsistent column %s: %s' % (name, exc))
                    cbFun(varBind, **dict(context, error=exc))
                    return

            if not count[0]:
                cbFun(varBind, **context)
                return

        colLen = len(self.name) + 1

        for colName, colObj in self._vars.items():
            instName = colName + name[colLen:]

            colObj.readGet((instName, None), **dict(context, cbFun=_cbFun))

            debug.logger & debug.FLAG_INS and debug.logger(
                '%s: _checkColumns: checking instance %s' % (self, instName))

    def writeTest(self, varBind, **context):
        """Test the ability to create/destroy or modify Managed Object Instance.

        Implements the first of the multi-step workflow of the SNMP SET
        command processing (:RFC:`1905#section-4.2.5`). On top of that,
        handles possible SMI table management events i.e. row creation
        and destruction via :class:`RowStatus` columnar object.

        The goal of the first phase is to make sure that requested Managed
        Object Instance could potentially be changed or created or destroyed.
        When multiple Managed Objects Instances are modified at once (likely
        coming all in one SNMP PDU), each of them has to run through the first
        (*test*) phase successfully for the system to transition to the second
        (*commit*) phase.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to set

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `acFun` (callable) - user-supplied callable that is invoked to
               authorize access to the requested Managed Object Instance. If
               not supplied, no access control will be performed.

        Notes
        -----
        The callback functions (e.g. `cbFun`, `acFun`) have the same signature
        as this method where `varBind` contains the new Managed Object Instance
        value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: writeTest(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        def _cbFun(varBind, **context):
            exc = context.get('error')
            if exc:
                instances[idx] = exc

                if isinstance(exc, error.RowCreationWanted):
                    def _cbFun(*args, **context):
                        self.announceManagementEvent('createTest', varBind, **dict(context, cbFun=cbFun))

                    self._manageColumns('createTest', varBind, **dict(context, cbFun=_cbFun, error=None))
                    return

                if isinstance(exc, error.RowDestructionWanted):
                    def _cbFun(*args, **context):
                        self.announceManagementEvent('destroyTest', varBind, **dict(context, cbFun=cbFun))

                    self._manageColumns('destroyTest', varBind, **dict(context, cbFun=_cbFun, error=None))
                    return

                if isinstance(exc, error.RowConsistencyWanted):
                    context['error'] = None

            cbFun(varBind, **context)

        ManagedMibObject.writeTest(self, varBind, **dict(context, cbFun=_cbFun))

    def writeCommit(self, varBind, **context):
        """Create/destroy or modify Managed Object Instance.

        Implements the second of the multi-step workflow of the SNMP SET
        command processing (:RFC:`1905#section-4.2.5`). On top of that,
        handles possible SMI table management events i.e. row creation
        and destruction via :class:`RowStatus` columnar object.

        The goal of the second phase is to actually modify the requested Managed
        Object Instance. When multiple Managed Objects Instances are modified at
        once (likely coming all in one SNMP PDU), each of them has to run through
        the second (*commit*) phase successfully for the system to transition to
        the third (*cleanup*) phase. If any single *commit* step fails, the system
        transitions into the *undo* state for each of Managed Objects Instances
        being processed at once.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to set

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `instances` (dict): user-supplied dict for temporarily holding
              the values of the Managed Objects Instances being modified.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature
        as this method where `varBind` contains the new Managed Object Instance
        value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: writeCommit(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        def _cbFun(varBind, **context):
            if idx in instances:
                exc = instances[idx]
                if isinstance(exc, error.RowCreationWanted):

                    def _cbFun(*args, **context):
                        exc = context.get('error')
                        if exc:
                            cbFun(varBind, **context)
                            return

                        def _cbFun(*args, **context):
                            self.announceManagementEvent('createCommit', varBind, **dict(context, cbFun=cbFun))

                        self._checkColumns(varBind, **dict(context, cbFun=_cbFun))

                    self._manageColumns('createCommit', varBind, **dict(context, cbFun=_cbFun))
                    return

                if isinstance(exc, error.RowDestructionWanted):
                    def _cbFun(*args, **context):
                        self.announceManagementEvent('destroyCommit', varBind, **dict(context, cbFun=cbFun))

                    self._manageColumns('destroyCommit', varBind, **dict(context, cbFun=_cbFun))
                    return

                if isinstance(exc, error.RowConsistencyWanted):
                    self._checkColumns(varBind, **dict(context, cbFun=cbFun))
                    return

            cbFun(varBind, **context)

        ManagedMibObject.writeCommit(self, varBind, **dict(context, cbFun=_cbFun))

    def writeCleanup(self, varBind, **context):
        """Finalize Managed Object Instance modification.

        Implements the successful third step of the multi-step workflow of the
        SNMP SET command processing (:RFC:`1905#section-4.2.5`). On top of that,
        handles possible SMI table management events i.e. row creation and
        destruction via :class:`RowStatus` columnar object.

        The goal of the third (successful) phase is to seal the new state of the
        requested Managed Object Instance. Once the system transition into the
        *cleanup* state, no roll back to the previous Managed Object Instance
        state is possible.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to set

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `instances` (dict): user-supplied dict for temporarily holding
              the values of the Managed Objects Instances being modified.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains the new Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: writeCleanup(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        def _cbFun(varBind, **context):
            if idx in instances:
                exc = instances.pop(idx)
                if isinstance(exc, error.RowCreationWanted):
                    def _cbFun(*args, **context):
                        self.announceManagementEvent('createCleanup', varBind, **dict(context, cbFun=cbFun))

                    self._manageColumns('createCleanup', varBind, **dict(context, cbFun=_cbFun))
                    return

                if isinstance(exc, error.RowDestructionWanted):
                    def _cbFun(*args, **context):
                        self.announceManagementEvent('destroyCleanup', varBind, **dict(context, cbFun=cbFun))

                    self._manageColumns('destroyCleanup', varBind, **dict(context, cbFun=_cbFun))
                    return

            cbFun(varBind, **context)

        ManagedMibObject.writeCleanup(self, varBind, **dict(context, cbFun=_cbFun))

    def writeUndo(self, varBind, **context):
        """Undo Managed Object Instance modification.

        Implements the third (unsuccessful) step of the multi-step workflow
        of the SNMP SET command processing (:RFC:`1905#section-4.2.5`). On top
        of that, handles possible SMI table management events i.e. row creation
        and destruction via :class:`RowStatus` columnar object.

        The goal of the third phase is to roll the Managed Object Instance
        being modified back into its previous state. The system transitions
        into the *undo* state whenever any of the simultaneously modified
        Managed Objects Instances fail on the *commit* state transitioning.

        The role of this object in the MIB tree is non-terminal. It does not
        access the actual Managed Object Instance, but just traverses one level
        down the MIB tree and hands off the query to the underlying objects.

        Parameters
        ----------
        varBind: :py:class:`~pysnmp.smi.rfc1902.ObjectType` object representing
            new Managed Object Instance value to set

        Other Parameters
        ----------------
        \*\*context:

            Query parameters:

            * `cbFun` (callable) - user-supplied callable that is invoked to
              pass the new value of the Managed Object Instance or an error.

            * `instances` (dict): user-supplied dict for temporarily holding
              the values of the Managed Objects Instances being modified.

        Notes
        -----
        The callback functions (e.g. `cbFun`) have the same signature as this
        method where `varBind` contains the new Managed Object Instance value.

        In case of an error, the `error` key in the `context` dict will contain
        an exception object.
        """
        name, val = varBind

        (debug.logger & debug.FLAG_INS and
         debug.logger('%s: writeUndo(%s, %r)' % (self, name, val)))

        cbFun = context['cbFun']

        instances = context['instances'].setdefault(self.name, {self.ST_CREATE: {}, self.ST_DESTROY: {}})
        idx = context['idx']

        def _cbFun(varBind, **context):
            if idx in instances:
                exc = instances.pop(idx)
                if isinstance(exc, error.RowCreationWanted):
                    def _cbFun(*args, **context):
                        self.announceManagementEvent('createUndo', varBind, **dict(context, cbFun=cbFun))

                    self._manageColumns('createUndo', varBind, **dict(context, cbFun=_cbFun))
                    return

                if isinstance(exc, error.RowDestructionWanted):
                    def _cbFun(*args, **context):
                        self.announceManagementEvent('destroyUndo', varBind, **dict(context, cbFun=cbFun))

                    self._manageColumns('destroyUndo', varBind, **dict(context, cbFun=_cbFun))
                    return

            cbFun(varBind, **context)

        ManagedMibObject.writeUndo(self, varBind, **dict(context, cbFun=_cbFun))

    # Table row management

    # Table row access by instance name

    def getInstName(self, colId, instId):
        return self.name + (colId,) + instId

    # Table index management

    def getIndicesFromInstId(self, instId):
        """Return index values for instance identification"""
        if instId in self._idToIdxCache:
            return self._idToIdxCache[instId]

        indices = []
        for impliedFlag, modName, symName in self._indexNames:
            mibObj, = mibBuilder.importSymbols(modName, symName)
            try:
                syntax, instId = self.oidToValue(mibObj.syntax, instId, impliedFlag, indices)
            except PyAsn1Error as exc:
                debug.logger & debug.FLAG_INS and debug.logger(
                    'error resolving table indices at %s, %s: %s' % (self.__class__.__name__, instId, exc))
                indices = [instId]
                instId = ()
                break

            indices.append(syntax)  # to avoid cyclic refs

        if instId:
            raise error.SmiError(
                'Excessive instance identifier sub-OIDs left at %s: %s' %
                (self, instId)
            )

        indices = tuple(indices)
        self._idToIdxCache[instId] = indices

        return indices

    def getInstIdFromIndices(self, *indices):
        """Return column instance identification from indices"""
        try:
            return self._idxToIdCache[indices]
        except TypeError:
            cacheable = False
        except KeyError:
            cacheable = True
        idx = 0
        instId = ()
        parentIndices = []
        for impliedFlag, modName, symName in self._indexNames:
            if idx >= len(indices):
                break
            mibObj, = mibBuilder.importSymbols(modName, symName)
            syntax = mibObj.syntax.clone(indices[idx])
            instId += self.valueToOid(syntax, impliedFlag, parentIndices)
            parentIndices.append(syntax)
            idx += 1
        if cacheable:
            self._idxToIdCache[indices] = instId
        return instId

    # Table access by index

    def getInstNameByIndex(self, colId, *indices):
        """Build column instance name from components"""
        return self.name + (colId,) + self.getInstIdFromIndices(*indices)

    def getInstNamesByIndex(self, *indices):
        """Build column instance names from indices"""
        instNames = []
        for columnName in self._vars.keys():
            instNames.append(
                self.getInstNameByIndex(*(columnName[-1],) + indices)
            )

        return tuple(instNames)


class MibTable(ManagedMibObject):
    """Managed MIB table object.

    Represents SMI table object (`OBJECT-TYPE`) implementing
    management instrumentation.

    Objects of this type can't carry any value of their own and do not play
    any part in table management.

    In the MIB tree, :class:`MibTable` objects reside right under the tree
    top and do not have any children.

        MibTree
           |
           +----MibTable
           |
           +----MibTableRow
                    |
                    +-----MibTableColumn
    """


zeroDotZero = ObjectIdentity((0, 0))

# OID tree
itu_t = MibScalar((0,)).setLabel('itu-t')
iso = MibTree((1,))
#joint_iso_itu_t = MibScalar((2,)).setLabel('joint-iso-itu-t')
org = MibIdentifier(iso.name + (3,))
dod = MibIdentifier(org.name + (6,))
internet = MibIdentifier(dod.name + (1,))
directory = MibIdentifier(internet.name + (1,))
mgmt = MibIdentifier(internet.name + (2,))
mib_2 = MibIdentifier(mgmt.name + (1,)).setLabel('mib-2')
transmission = MibIdentifier(mib_2.name + (10,))
experimental = MibIdentifier(internet.name + (3,))
private = MibIdentifier(internet.name + (4,))
enterprises = MibIdentifier(private.name + (1,))
security = MibIdentifier(internet.name + (5,))
snmpV2 = MibIdentifier(internet.name + (6,))

snmpDomains = MibIdentifier(snmpV2.name + (1,))
snmpProxys = MibIdentifier(snmpV2.name + (2,))
snmpModules = MibIdentifier(snmpV2.name + (3,))

mibBuilder.exportSymbols(
    'SNMPv2-SMI', MibNode=MibNode,
    Integer32=Integer32, Bits=Bits, IpAddress=IpAddress,
    Counter32=Counter32, Gauge32=Gauge32, Unsigned32=Unsigned32,
    TimeTicks=TimeTicks, Opaque=Opaque, Counter64=Counter64,
    ExtUTCTime=ExtUTCTime,
    ModuleIdentity=ModuleIdentity, ObjectIdentity=ObjectIdentity,
    NotificationType=NotificationType, MibScalar=MibScalar,
    MibScalarInstance=MibScalarInstance,
    MibIdentifier=MibIdentifier, MibTree=MibTree,
    MibTableColumn=MibTableColumn, MibTableRow=MibTableRow,
    MibTable=MibTable, zeroDotZero=zeroDotZero,
    itu_t=itu_t, iso=iso, org=org, dod=dod,
    internet=internet, directory=directory, mgmt=mgmt, mib_2=mib_2,
    transmission=transmission, experimental=experimental, private=private,
    enterprises=enterprises, security=security, snmpV2=snmpV2,
    snmpDomains=snmpDomains, snmpProxys=snmpProxys, snmpModules=snmpModules
)

# XXX
# getAsName/setFromName goes out of MibRow?
# revisit getNextNode() -- needs optimization
