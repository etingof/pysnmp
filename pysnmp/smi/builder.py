# MIB modules loader
import os
from pysnmp.smi import error
try:
    import pysnmp_mibs
except ImportError:
    pysnmp_mibs = None

class MibBuilder:
    def __init__(self):
        self.lastBuildId = self._autoName = 0L
        paths = (
            os.path.join(os.path.split(error.__file__)[0], 'mibs','instances'),
            os.path.join(os.path.split(error.__file__)[0], 'mibs')
            )
        if os.environ.has_key('PYSNMP_MIB_DIR'):
            paths = paths + (
                os.path.join(os.path.split(os.environ['PYSNMP_MIB_DIR'])[0]),
                )
        if pysnmp_mibs:
            paths = paths + (
                os.path.join(os.path.split(pysnmp_mibs.__file__)[0]),
                )
        self.mibSymbols = {}
        self.__modSeen = {}
        self.__modPathsSeen = {}
        apply(self.setMibPath, paths)
        
    # MIB modules management
    
    def setMibPath(self, *mibPaths):
        self.__modSeen.clear()
        self.__mibPaths = map(os.path.normpath, mibPaths)

    def getMibPath(self): return tuple(self.__mibPaths)
        
    def loadModules(self, *modNames):
        # Build a list of available modules
        if not modNames:
            modNames = {}
            for mibPath in self.__mibPaths:
                try:
                    for modName in os.listdir(mibPath):
                        if modName[0] == '_' or modName[-3:] != '.py':
                            continue
                        modNames[modName[:-3]] = None
                except OSError:
                    continue
            modNames = modNames.keys()
        if not modNames:
            raise error.SmiError(
                'No MIB module to load at %s' % (self,)
                )
        for modName in modNames:
            for mibPath in self.__mibPaths:
                modPath = os.path.join(
                    mibPath, modName + '.py'
                    )

                try:
                    open(modPath).close()
                except IOError:
                    continue

                if self.__modPathsSeen.has_key(modPath):
                    continue
                else:
                    self.__modPathsSeen[modPath] = 1

                g = { 'mibBuilder': self }

                try:
                    execfile(modPath, g)
                except StandardError, why:
                    del self.__modPathsSeen[modPath]
                    raise error.SmiError(
                        'MIB module \"%s\" load error: %s' % (modPath, why)
                        )

                self.__modSeen[modName] = 1

            if not self.__modSeen.has_key(modName):
                raise error.SmiError(
                    'MIB file \"%s.py\" not found in search path' % modName
                    )

        return self
                
    def unloadModule(self, *modNames):
        return self

    def importSymbols(self, modName, *symNames):
        r = ()
        for symName in symNames:
            if not self.mibSymbols.has_key(modName):
                self.loadModules(modName)
            if not self.mibSymbols.has_key(modName):
                raise error.SmiError(
                    'No module %s loaded at %s' % (modName, self)
                    )
            if not self.mibSymbols[modName].has_key(symName):
                raise error.SmiError(
                    'No symbol %s::%s at %s' % (modName, symName, self)
                    )
            r = r + (self.mibSymbols[modName][symName],)
        return r

    def exportSymbols(self, modName, *anonymousSyms, **namedSyms):
        if not self.mibSymbols.has_key(modName):
            self.mibSymbols[modName] = {}
        mibSymbols = self.mibSymbols[modName]
        
        for symObj in anonymousSyms:
            mibSymbols['__pysnmp_%ld' % self._autoName] = symObj
            self._autoName = self._autoName + 1
            
        for symName, symObj in namedSyms.items():
            if mibSymbols.has_key(symName):
                raise error.SmiError(
                    'Symbol %s already exported at %s' % (symName, modName)
                    )
            if hasattr(symObj, 'label') and symObj.label:
                symName = symObj.label
            mibSymbols[symName] = symObj
            
        self.lastBuildId = self.lastBuildId + 1
