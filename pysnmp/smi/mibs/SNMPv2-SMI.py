from string import join, split
from pysnmp.smi.indices import OidOrderedDict
from pysnmp.smi import error
from pysnmp.proto import rfc1902
from pysnmp.asn1 import subtypes
from pysnmp.asn1.error import ValueConstraintError

( OctetString,
  ObjectIdentifier,
  Integer ) = mibBuilder.importSymbols(
    'ASN1',
    'OctetString',
    'ObjectIdentifier',
    'Integer'
    )

# syntax of objects

Bits = rfc1902.Bits
Integer32 = rfc1902.Integer32
IpAddress = rfc1902.IpAddress
Counter32 = rfc1902.Counter32
Gauge32 = rfc1902.Gauge32
Unsigned32 = rfc1902.Unsigned32
TimeTicks = rfc1902.TimeTicks
Opaque = rfc1902.Opaque
Counter64 = rfc1902.Counter64

class ExtUTCTime(OctetString):
    subtypeConstraints = OctetString.subtypeConstraints + (
        subtypes.ValueSizeConstraint(0, 13),
        )

# MIB tree foundation classes

class MibNodeBase:
    def __init__(self, name=()):
        self.name = name
        self.label = ''
        
    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, self.name)

    def setName(self, name):
        self.name = name
        return self

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

class ModuleIdentity(MibNodeBase):
    def getLastUpdated(self):
        return getattr(self, 'lastUpdated', '')
    def setLastUpdated(self, v):
        self.lastUpdated = v
        return self
    def getOrganization(self):
        return getattr(self, 'organization', '')
    def setOrganization(self, v):
        self.organization = v
        return self
    def getContactInfo(self):
        return getattr(self, 'contactInfo', '')
    def setContactInfo(self, v):
        self.contactInfo = v
        return self
    def getDescription(self):
        return getattr(self, 'description', '')
    def setDescription(self, v):
        self.description = v
        return self
    def getRevisions(self):
        return getattr(self, 'revisions', ())
    def setRevisions(self, *args):
        self.revisions = args
        return self

class ObjectIdentity(MibNodeBase):
    def getStatus(self):
        return getattr(self, 'status', 'current')
    def setStatus(self, v):
        self.status = v
        return self
    def getDescription(self):
        return getattr(self, 'description', '')
    def setDescription(self, v):
        self.description = v
        return self
    def getReference(self):
        return getattr(self, 'reference', '')
    def setReference(self, v):
        self.reference = v
        return self

# definition for objects

class NotificationType(MibNodeBase):
    def getObjects(self):
        return getattr(self, 'objects', ())
    def setObjects(self, *args):
        self.objects = args
        return self
    def getStatus(self):
        return getattr(self, 'status', 'current')
    def setStatus(self, v):
        self.status = v
        return self
    def getDescription(self):
        return getattr(self, 'description', '')
    def setDescription(self, v):
        self.description = v
        return self
    def getRevisions(self):
        return getattr(self, 'revisions', ())
    def setRevisions(self, *args):
        self.revisions = args
        return self

class MibIdentifier(MibNodeBase): pass

class ObjectTypePattern(MibNodeBase):
    maxAccess = None
    def getSyntax(self):
        return getattr(self, 'syntax', None)   # XXX
    def getSyntaxClone(self):
        # May be used to preserve backend instrumentation settings
        # whenever SNMP engine shares the same MIB for manager & agent roles
        if hasattr(self, 'syntaxClone'):
            return self.syntaxClone
        self.syntaxClone = self.getSyntax()
        if self.syntaxClone is not None:
            self.syntaxClone = self.syntaxClone.clone()
        return self.syntaxClone
    def setSyntax(self, v):
        self.syntax = v
        return self
    def getUnits(self):
        return getattr(self, 'units', '')
    def setUnits(self, v):
        self.units = v
        return self    
    def getMaxAccess(self):
        return getattr(self, 'maxAccess', 'not-accessible')
    def setMaxAccess(self, v):
        self.maxAccess = v
        return self
    def getStatus(self):
        return getattr(self, 'status', 'current')
    def setStatus(self, v):
        self.status = v
        return self
    def getDescription(self):
        return getattr(self, 'description', '')
    def setDescription(self, v):
        self.description = v
        return self    
    def getReference(self):
        return getattr(self, 'reference', '')
    def setReference(self, v):
        self.reference = v
        return self
        
class MibVariable(ObjectTypePattern):
    """Scalar MIB variable instance. Implements read/write operations."""
    maxAccess = 'readonly'
    def __init__(self, name=None, syntax=None):
        ObjectTypePattern.__init__(self, name)
        if syntax is not None:
            self.setSyntax(syntax)
        self.__newValue = None
        
    def __repr__(self):
        return '%s(%s, %s)' % (
            self.__class__.__name__, self.name, self.syntax
            )

    def __cmp__(self, other): return cmp(self.syntax, other)
    
    def clone(self, name=None, syntax=None):
        myClone = ObjectTypePattern.clone(self, name)
        myClone.maxAccess = self.maxAccess
        # XXX constr checking on initialisation
        if syntax is not None:
            myClone.syntax = syntax
        elif self.syntax is not None:
            # XXX clone the rest of attrs
            myClone.syntax = self.syntax.clone()
        return myClone

    def getNode(self, name):
        # Recursion terminator
        if name == self.name:
            return self
        raise error.NoSuchInstanceError(
            'No such name %s at %s' % (name, self)
            )

    def getNextNode(self, name):
        # Recursion terminator
        raise error.NoSuchInstanceError(
            'No next name %s at leaf %s' % (name, self)
            )

    # MIB instrumentation methods
    
    # Read operation
    
    def readTest(self, name, val):
        if name == self.name:
            if self.maxAccess != 'readonly' and \
               self.maxAccess != 'readwrite' and \
               self.maxAccess != 'readcreate':
                raise error.NoAccessError(
                    'No read access to variable %s' % str(name)
                    )
        else:
            raise error.NoSuchInstanceError(
                'Variable %s does not exist at %s' % (name, self)
                )
    
    def readGet(self, name, val):
        # Return current variable (name, value). This is the only API method
        # capable of returning anything!
        if name == self.name:
            return self.name, self.syntax
    
    # Two-phase commit implementation

    def writeTest(self, name, val):
        # Make sure write's allowed
        if name == self.name:
            # make sure variable is writable
            if self.maxAccess != 'readwrite' and \
               self.maxAccess != 'readcreate':
                raise error.NotWritableError(
                    'No write access to variable %s at %s' % (name, self)
                    )
        else:
            raise error.NoSuchInstanceError(
                'Variable %s does not exist at %s' % (name, self)
                )
        self.__newSyntax = self.syntax.clone()
        self.__newSyntax.set(val)

    def writeCommit(self, name, val):
        # Commit new value
        self.syntax, self.__newSyntax = self.__newSyntax, self.syntax
        
    def writeCleanup(self, name, val):
        # Drop previous value
        self.__newSyntax = None
    
    def writeUndo(self, name, val):
        # Revive previous value
        self.syntax, self.__newSyntax = self.__newSyntax, None

class MibTree(ObjectTypePattern):
    branchVersionId = 0L    # increments on tree structure change XXX
    defaultVars = None
    maxAccess = 'not-accessible'
    def __init__(self, name=None, *vars):
        ObjectTypePattern.__init__(self, name)
        self._vars = OidOrderedDict()            
        if vars:
            apply(self.registerSubtrees, vars)
        if self.defaultVars:
            apply(self.registerSubtrees,
                  map(lambda x: x.clone(), self.defaultVars)
                  )

    # Subtrees registration
    
    def registerSubtrees(self, *subTrees):
        """Register subtrees at this tree. Subtrees are always attached
           at the level of this tree, not subtrees."""
        for subTree in subTrees:
            if self._vars.has_key(subTree.name):
                continue
# XXX complain?
#                 if self._vars[subTree.name] is subTree:
#                     continue
#                 raise error.SmiError(
#                     'MIB subtree %s already registered %s' % \
#                     (subTree.name, self)
#                     )
            self._vars[subTree.name] = subTree
            MibTree.branchVersionId = MibTree.branchVersionId + 1

    def unregisterSubtrees(self, *subTrees):
        """Detach subtrees from this tree"""
        for subTree in subTrees:
            if self._vars.has_key(subTree.name):
                del self._vars[subTree.name]
                MibTree.branchVersionId = MibTree.branchVersionId + 1

    # Tree traversal

    def getBranch(self, name):
        """Return a branch of this tree where the 'name' OID may reside"""
        subName = tuple(name)
        subNameLen = len(self.name)
        while subNameLen < len(subName):
            if self._vars.has_key(subName):
                return self._vars[subName]
            subName = subName[:-1]
        else:
            raise error.NoSuchInstanceError(
                'Name %s does not exist at %s' % (name, self)
                )

    def getNode(self, name):
        """Return tree node found by name"""
        if name == self.name:
            return self
        else:
            return self.getBranch(name).getNode(name)

    def getNextNode(self, name):
        """Return tree node next to name"""
        try:
            nextNode = self.getBranch(name)
        except error.NoSuchInstanceError:
            # Start from the beginning
            if self._vars and name <= self._vars.keys()[0]:
                return self._vars[self._vars.keys()[0]]
            else:
                raise
        else:
            try:
                return nextNode.getNextNode(name)
            except error.NoSuchInstanceError:
                try:
                    return self._vars[self._vars.nextKey(nextNode.name)]
                except KeyError:
                    raise error.NoSuchInstanceError(name)
                
    # Mapping interface to subtree XXX
    
    def get(self, key, defVal=None): return self._vars.get(key, defVal)
    def keys(self): return self._vars.keys()
    
    # MIB instrumentation

    # Read operation
    
    def readTest(self, name, val):
        if name == self.name:
            if self.maxAccess != 'readonly' and \
                   self.maxAccess != 'readwrite' and \
                   self.maxAccess != 'readcreate':
                raise error.NoAccessError(
                    'No read access to variable at %s' % self
                    )
        else:
            node = self.getBranch(name)

# XXX
#            if not isinstance(node, ObjectTypePattern):
#                raise error.NoAccessError(
#                    'Not ObjectType macro instance at %s' % self
#                    )
            node.readTest(name, val)
        
    def readGet(self, name, val):
        return self.getBranch(name).readGet(name, val)

    # Read next operation is subtree-specific
    
    def readTestNext(self, name, val):
        nextName = name
        while 1:
            nextName = self.getNextNode(nextName).name
            try:
                return self.readTest(nextName, val)
            except error.NoAccessError:
                continue
    
    def readGetNext(self, name, val):
        nextName = name
        while 1:
            nextName = self.getNextNode(nextName).name
            if nextName:
                try:
                    self.readTest(nextName, val) # XXX
                except error.NoAccessError:
                    continue
                else:
                    return self.readGet(nextName, val)
            else:
                raise error.NoSuchInstanceError(
                    'Variable next to %s does not exist at %s' % (name, self)
                    )

    # Write operation
    
    def writeTest(self, name, val):
        if name == self.name:
            # Make sure variable is writable
            if self.maxAccess != 'readwrite' and \
                   self.maxAccess != 'readcreate':
                raise error.NotWritableError(
                    'No write access to variable %s at %s' % (name, self)
                    )
        else:
            node = self.getBranch(name)
# XXX
#            if not isinstance(node, ObjectTypePattern): # XXX
#                raise error.NoAccessError(
#                    'Not ObjectType macro instance at %s' % self
#                    )
            node.writeTest(name, val)
    
    def writeCommit(self, name, val):
        self.getBranch(name).writeCommit(name, val)
    
    def writeCleanup(self, name, val):
        self.getBranch(name).writeCleanup(name, val)
    
    def writeUndo(self, name, val):
        self.getBranch(name).writeUndo(name, val)

# Conceptual table classes

class MibTableColumn(MibTree):
    """MIB table column. Manages a set of column instance variables"""
    defaultColumnInitializer = None

    def __init__(self, name=None, *vars):
        apply(MibTree.__init__, (self, name) + vars)
        if self.defaultColumnInitializer is not None:
            self.setColumnInitializer(self.defaultColumnInitializer.clone())
        else:
            self.columnInitializer = None
        self.__createdInstances = {}; self.__destroyedInstances = {}
        self.__rowOpWanted = {}

    def setColumnInitializer(self, mibVar):
        self.columnInitializer = mibVar
        self.columnInitializer.name = self.name
        return self

    def getColumnInitializer(self):
        if self.columnInitializer is None:
            raise error.SmiError(
                'Uninitialized column syntax at %s' % (self)
                )
        return self.columnInitializer

    def getSyntax(self):
        if self.columnInitializer is not None:
            return getattr(self.columnInitializer, 'syntax', None)
        
    # Column creation (this should probably be converted into some state
    # machine for clarity). Also, it might be a good idea to inidicate
    # defaulted cols creation in a clearer way than just a val == None.
    
    def createTest(self, name, val=None):
        # Make sure creation allowed, create a new column instance but
        # do not replace the old one
        if self._vars.has_key(name):
            return
        if val is not None and \
               self.columnInitializer.maxAccess != 'readcreate':
            raise error.NoCreationError(
                'Column instance creation prohibited at %s' % self
                )
        if not self.__createdInstances.has_key(name):            
            self.__createdInstances[name] = self.columnInitializer.clone(
                name
                )
        if val is not None:
            try:
                self.__createdInstances[name].writeTest(name, val)
            except (error.RowCreationWanted, error.RowDestructionWanted):
                pass
            
    def createCommit(self, name, val=None):
        # Commit new instance value
        if self._vars.has_key(name):
            if self.__createdInstances.has_key(name):
                if val is not None:
                    self._vars[name].writeCommit(name, val)
            return
        if val is not None:
            self.__createdInstances[name].writeCommit(name, val)
        # ...commit new column instance
        self._vars[name], self.__createdInstances[name] = \
                          self.__createdInstances[name], self._vars.get(name)

    def createCleanup(self, name, val=None):
        # Drop previous column instance
        if self.__createdInstances.has_key(name):
            if self.__createdInstances[name] is not None:
                self.__createdInstances[name].writeCleanup(name, val)
            del self.__createdInstances[name]
        elif self._vars.has_key(name):
            self._vars[name].writeCleanup(name, val)
        
    def createUndo(self, name, val=None):
        # Set back previous column instance, drop the new one
        if self.__createdInstances.has_key(name):
            self._vars[name] = self.__createdInstances[name]
            del self.__createdInstances[name]            
            # Remove new instance on rollback
            if self._vars[name] is None:
                del self._vars[name]
            else:
                self._vars[name].writeUndo(name, val)
                
    # Column destruction
        
    def destroyTest(self, name, val=None):
        # Make sure destruction is allowed
        if self._vars.has_key(name):
            if val is not None and \
                   self.columnInitializer.maxAccess != 'readcreate':
                raise error.NoAccessError(
                    'Column instance destruction prohibited at %s' % self
                    )

    def destroyCommit(self, name, val=None):
        # Make a copy of column instance and take it off the tree
        if self._vars.has_key(name):
            self.__destroyedInstances[name] = self._vars[name]
            del self._vars[name]
        
    def destroyCleanup(self, name, val=None):
        # Drop instance copy
        if self.__destroyedInstances.has_key(name):
            del self.__destroyedInstances[name]
            
    def destroyUndo(self, name, val=None):
        # Set back column instance
        if self.__destroyedInstances.has_key(name):
            self._vars[name] = self.__destroyedInstances[name]
            del self.__destroyedInstances[name]
            
    # Set/modify column

    def writeTest(self, name, val):
        # Besides common checks, request row creation on no-instance
        try:
            # First try the instance
            MibTree.writeTest(self, name, val)
        # ...otherwise proceed with creating new column
        except (error.NoSuchInstanceError, error.RowCreationWanted):
            self.__rowOpWanted[name] =  error.RowCreationWanted()
            self.createTest(name, val)
        except error.RowDestructionWanted:
            self.__rowOpWanted[name] =  error.RowDestructionWanted()
            self.destroyTest(name, val)
        if self.__rowOpWanted.has_key(name):
            raise self.__rowOpWanted[name]

    def __delegateWrite(self, subAction, name, val):
        if not self.__rowOpWanted.has_key(name):
            getattr(MibTree, 'write'+subAction)(self, name, val)
            return
        if isinstance(self.__rowOpWanted[name], error.RowCreationWanted):
            getattr(self, 'create'+subAction)(name, val)
        if isinstance(self.__rowOpWanted[name], error.RowDestructionWanted):
            getattr(self, 'destroy'+subAction)(name, val)            
        raise self.__rowOpWanted[name]

    def writeCommit(self, name, val):
        self.__delegateWrite('Commit', name, val)

    def writeCleanup(self, name, val):
        self.__delegateWrite('Cleanup', name, val)
        if self.__rowOpWanted.has_key(name):
            del self.__rowOpWanted[name]
            
    def writeUndo(self, name, val):
        self.__delegateWrite('Undo', name, val)
        if self.__rowOpWanted.has_key(name):
            del self.__rowOpWanted[name]

class MibTableRow(MibTree):
    """MIB table row (SMI 'Entry'). Manages a set of table columns.
       Implements row creation/destruction.
    """
    defaultIndexNames = None    # XXX indexNames ?
    
    def __init__(self, name=None, *vars):
        apply(MibTree.__init__, (self, name) + vars)
        if self.defaultIndexNames is not None:
            self.setIndexNames(self.defaultIndexNames)
        else:
            self.indexNames = ()
        self.augmentingRows = {}

    # Table indices resolution

    __intValue = Integer()
    __strValue = OctetString()
    __oidValue = ObjectIdentifier()
    __ipaddrValue = IpAddress()

    def setFromName(self, obj, value, impliedFlag=None):
        if self.__intValue.isSubtype(obj):
            obj.set(value[0])
            return value[1:]
        elif self.__ipaddrValue.isSubtype(obj):
            obj.set(join(map(str, value[:4]), '.'))
            return value[4:]
        elif self.__strValue.isSubtype(obj):
            if impliedFlag:
                s = reduce(lambda x,y: x+y, map(lambda x: chr(x), value))
            else:
                s = reduce(lambda x,y: x+y, map(lambda x: chr(x), value[1:]))
                # XXX check name vs str length
            valueLength = len(s)
            while valueLength:
                try:
                    obj.set(s[:valueLength])
                    s = s[valueLength:]
                    # XXX
                    if impliedFlag:
                        initial = ()
                    else:
                        initial = (len(obj),)
                    return reduce(
                        lambda x,y: x+(y,), map(lambda x: ord(x), s), initial
                        )
                except ValueConstraintError:
                    valueLength = valueLength - 1
                raise error.SmiError(
                    'Instance ID %s does not fit INDEX %s' % (value, obj)
                    )
        elif self.__oidValue.isSubtype(obj):
            if impliedFlag:
                obj.set(value)
            else:
                obj.set(value[1:])
            return ()
        else:
            obj.set(value)
            return ()
            
    def getAsName(self, obj, impliedFlag=None):
        if self.__intValue.isSubtype(obj):
            return (obj.get())
        elif self.__strValue.isSubtype(obj):
            if impliedFlag:
                initial = ()
            else:
                initial = (len(obj),)
            return reduce(
                lambda x,y: x+(y,), map(lambda x: ord(x), obj), initial
                )
        elif self.__oidValue.isSubtype(obj):
            if impliedFlag:
                return tuple(self)
            else:
                return (len(self),) + tuple(self)            
        elif self.__ipaddrValue.isSubtype(obj):
            return tuple(map(int, split(obj.get(), '.')))
        else:
            return (obj.get())
            
    # Fate sharing mechanics

    def announceManagementEvent(self, action, name):
        # Convert OID suffix into index vals
        instId = name[len(self.name)+1:]
        baseIndices = []
        for impliedFlag, modName, symName in self.indexNames:
            mibObj, = mibBuilder.importSymbols(modName, symName)
            instId = self.setFromName(
                mibObj.getColumnInitializer().syntax, instId, impliedFlag
                )
            if self.name == mibObj.name[:-1]:
                baseIndices.append(mibObj)
        if instId:
            raise error.SmiError(
                'Exsessive instance identifier sub-OIDs left at %s: %s' %
                (self, instId)
                )
        if not baseIndices:
            return
        for modName, mibSym in self.augmentingRows.keys():
             mibObj, = mibBuilder.importSymbols(modName, mibSym)
             mibObj.receiveManagementEvent(action, baseIndices)
            
    def receiveManagementEvent(self, action, baseIndices):
        # The default implementation supports one-to-one rows dependency
        newSuffix = ()
        # Resolve indices intersection
        for impliedFlag, mibMod, symName in self.indexNames:
            mibObj, = mibBuilder.importSymbols(modName, symName)
            for baseIndex in baseIndices:
                if baseIndex.name == mibObj.name:
                    newSuffix = newSuffix + \
                                self.getAsName(
                        baseIndex.getColumnInitializer().syntax, impliedFlag
                        )
        if newSuffix:
            self.__manageColumns(action, newSuffix)

    def registerAugmentions(self, *names):
        for modName, symName in names:
            if self.augmentingRows.has_key((modName, symName)):
                raise error.SmiError(
                    'Row %s already augmented by %s::%s' % \
                    (self.name, modName, symName)
                    )
            self.augmentingRows[(modName, symName)] = 1
        return self
        
    def setIndexNames(self, *names):
        for name in names:
#             if name in self.indexNames:
#                 raise error.SmiError(
#                     'Index %s already set to row %s' % (
#                     name, self
#                     ))
            self.indexNames = self.indexNames + (name,)
        return self

    def getIndexNames(self):
        return self.indexNames
                             
    def __manageColumns(self, action, nameSuffix):
        for name, var in self._vars.items():
            getattr(var, action)(name + nameSuffix)

    def __delegate(self, subAction, name, val):
        # Relay operation request to column, expect row operation request.
        
        try:
            getattr(self.getBranch(name), 'write'+subAction)(name, val)
        except error.RowCreationWanted, why:
            self.__manageColumns('create'+subAction, name[len(self.name)+1:])
            self.announceManagementEvent('create'+subAction, name)
        except error.RowDestructionWanted, why:
            self.__manageColumns('destroy'+subAction, name[len(self.name)+1:])
            self.announceManagementEvent('destroy'+subAction, name)
    
    def writeTest(self, name, val): self.__delegate('Test', name, val)
    def writeCommit(self, name, val): self.__delegate('Commit', name, val)
    def writeCleanup(self, name, val): self.__delegate('Cleanup', name, val)
    def writeUndo(self, name, val): self.__delegate('Undo', name, val)

    # Table row management
    
    # Table row access by instance name

    def getInstName(self, colId, instId):
        return self.name + (colId,) + instId

    # Table index management

    def getIndicesFromInstId(self, instId):
        """Return index values for instance identification"""
        indices = []
        for impliedFlag, modName, symName in self.indexNames:
            mibObj, = mibBuilder.importSymbols(modName, symName)
            val = mibObj.getColumnInitializer().syntax
            instId = self.setFromName(val, instId, impliedFlag)
            indices.append(val.get())
        if instId:
            raise error.SmiError(
                'Exsessive instance identifier sub-OIDs left at %s: %s' %
                (self, instId)
                )
        return tuple(indices)

    def getInstIdFromIndices(self, *indices):
        """Return column instance identification from indices"""
        idx = 0; instId = ()
        for impliedFlag, modName, symName in self.indexNames:
            mibObj, = mibBuilder.importSymbols(modName, symName)
            if idx < len(indices):
                instId = instId + self.getAsName(
                    mibObj.getColumnInitializer().syntax.set(indices[idx]),
                    impliedFlag
                    )
        return instId

    # Table access by index
    
    def getInstNameByIndex(self, colId, *indices):
        """Build column instance name from components"""
        return self.name + (colId,) + apply(
            self.getInstIdFromIndices, indices
            )

    def getInstNamesByIndex(self, *indices):
        """Build column instance names from indices"""
        instNames = []
        for columnName in self._vars.keys():
            instNames.append(
                apply(self.getInstNameByIndex,
                      (columnName[-1],) + indices)
                )
        return tuple(instNames)
    
class MibTable(MibTree):
    """MIB table. Manages a set of TableRow's"""

zeroDotZero = ObjectIdentity((0,0))

#dot = MibTree()
iso = MibTree((1,))
org = MibIdentifier(iso.name + (3,))
dod = MibIdentifier(org.name + (6,))
internet = MibIdentifier(dod.name + (1,))
directory = MibIdentifier(internet.name + (1,))
mgmt = MibIdentifier(internet.name + (2,))
mib_2 = MibIdentifier(mgmt.name + (1,)); mib_2.label = 'mib-2'
transmission = MibIdentifier(mib_2.name + (10,))
experimental = MibIdentifier(internet.name + (3,))
private = MibIdentifier(internet.name + (4,))
enterprises = MibIdentifier(private.name + (1,))
security = MibIdentifier(internet.name + (5,))
snmpV2 = MibIdentifier(internet.name + (6,))

snmpDomains = MibIdentifier(snmpV2.name + (1,))
snmpProxys = MibIdentifier(snmpV2.name +(2,))
snmpModules = MibIdentifier(snmpV2.name +(3,))

mibBuilder.exportSymbols(
    'SNMPv2-SMI', Integer32=Integer32, Bits=Bits, IpAddress=IpAddress,
    Counter32=Counter32,    Gauge32=Gauge32, Unsigned32=Unsigned32,
    TimeTicks=TimeTicks, Opaque=Opaque, Counter64=Counter64,
    ExtUTCTime=ExtUTCTime, MibNodeBase=MibNodeBase,
    ModuleIdentity=ModuleIdentity, ObjectIdentity=ObjectIdentity,
    NotificationType=NotificationType, MibVariable=MibVariable,
    MibIdentifier=MibIdentifier, MibTree=MibTree,
    MibTableColumn=MibTableColumn, MibTableRow=MibTableRow,
    MibTable=MibTable, zeroDotZero=zeroDotZero,
    iso=iso, org=org, dod=dod, internet=internet,
    directory=directory, mgmt=mgmt, mib_2=mib_2, transmission=transmission,
    experimental=experimental, private=private, enterprises=enterprises,
    security=security, snmpV2=snmpV2, snmpDomains=snmpDomains,
    snmpProxys=snmpProxys, snmpModules=snmpModules    
    )

# XXX
# maybe re-factor tree facilities
