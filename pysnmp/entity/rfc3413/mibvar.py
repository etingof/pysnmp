# MIB variable pretty printers/parsers
import types
from pysnmp.smi.error import NoSuchInstanceError

# Name

def instanceNameToOid(mibView, name):
    if type(name[0]) == types.TupleType:
        symName, modName = apply(lambda x,y='': (x,y), name[0])
        oid, label, suffix = mibView.getNodeNameByDesc(symName, modName)
        suffix = name[1:]
    else:
        oid, label, suffix = mibView.getNodeNameByOid(name)
    modName, symName, _s = mibView.getNodeLocation(oid)
    mibNode, = mibView.mibBuilder.importSymbols(
        modName, symName
        )
    if hasattr(mibNode, 'getColumnInitializer'): # table column
        modName, symName, _s = mibView.getNodeLocation(oid[:-1])
        rowNode, = mibView.mibBuilder.importSymbols(modName, symName)
        return oid, apply(rowNode.getInstIdFromIndices, suffix)
    else: # scalar or incomplete spec
        return oid, suffix

def oidToInstanceName(mibView, oid):
    oid, label, suffix = mibView.getNodeNameByOid(tuple(oid))
    modName, symName, __suffix = mibView.getNodeLocation(oid)
    mibNode, = mibView.mibBuilder.importSymbols(
        modName, symName
        )
    if hasattr(mibNode, 'getColumnInitializer'): # table column
        __modName, __symName, __s = mibView.getNodeLocation(oid[:-1])
        rowNode, = mibView.mibBuilder.importSymbols(__modName, __symName)
        return (symName, modName), rowNode.getIndicesFromInstId(suffix)
    elif suffix == (0,): # scalar
        return (symName, modName), suffix
    else:
        raise NoSuchInstanceError(
            str='No MIB info for %s' % (oid, )
            )

# Value

def cloneFromMibValue(mibView, modName, symName, value):
    mibNode, = mibView.mibBuilder.importSymbols(
        modName, symName
        )
    if hasattr(mibNode, 'getColumnInitializer'): # table column
        return mibNode.getColumnInitializer().syntax.clone(value)
    else:
        return mibNode.syntax.clone(value)
