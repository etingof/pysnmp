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
    # Instance ID
    if suffix == (0,): # scalar
        return oid + suffix
    else: # possible table cell
        modName, symName, _s = mibView.getNodeLocation(oid[:-1]) # XXX
        rowNode, = mibView.mibBuilder.importSymbols(modName, symName)
        if hasattr(rowNode, 'getInstIdFromIndices'): # table cell
            return apply(rowNode.getInstIdFromIndices, suffix)
        else: # incomplete spec
            return oid + suffix

def oidToIinstanceName(mibView, oid):
    oid, label, suffix = mibView.getNodeNameByOid(oid)
    if oid == label: # not resolved
        return label
    modName, mibSym, suffix = mibView.getNodeLocation(oid)        
    if suffix == (0,): # resolved to scalar
        return (symName, modName), suffix
    else: # possible table
        rowNode = mibView.mibBuilder.getNode(oid[:-1])
        return (symName, modName), label + rowNode.getIndicesFromInstId(
            suffix
            )

# Value

def prettyValueToObjectValue(mibView, objectName, prettyValue):
    mibNode = mibView.mibBuilder.getNode(objectName)
    return mibNode.syntax.clone(prettyValue)

def objectValueToPrettyValue(mibView, objectName, value):
    return prettyValueToObjectValue(mibView, objectName, prettyValue)
