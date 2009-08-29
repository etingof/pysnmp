# MIB modules loader
import os, types, string
from pysnmp.smi import error
from pysnmp import debug

class __BaseMibSource:
    def __init__(self, srcName):
        self._srcName = srcName        
        debug.logger & debug.flagBld and debug.logger('trying %s' % self)

    def __repr__(self):
        return '%s(\'%s\')' % (self.__class__.__name__, self._srcName)

    def fullPath(self, f=''):
        return self._srcName + (f and (os.path.sep + f + '.py') or '')

    def init(self): raise Exception('Method not implemented')
    def listdir(self): raise Exception('Method not implemented')
    def read(self, path): raise Exception('Method not implemented')

class ZipMibSource(__BaseMibSource):
    def init(self):
        p = __import__(
            self._srcName, globals(), locals(), string.split(self._srcName, '.')
            )
        if hasattr(p, '__loader__'):
            self.__loader = p.__loader__
            self._srcName = string.replace(self._srcName, '.', os.path.sep)
            return self
        else:
            return DirMibSource(os.path.split(p.__file__)[0]).init()
        
    def listdir(self):
        l = []
        for f in self.__loader._files.keys():
            d, f = os.path.split(f)
            if d == self._srcName and f != '__init__.py' and f[-3:] == '.py':
                l.append(f[:-3])
        return tuple(l)

    def read(self, f):
        return self.__loader.get_data(os.path.join(self._srcName, f) + '.py')
    
class DirMibSource(__BaseMibSource):
    def init(self):
        self._srcName = os.path.normpath(self._srcName)
        return self
    
    def listdir(self):
        l = []
        for f in os.listdir(self._srcName):
            if f != '__init__.py' and f[-3:] == '.py':
                l.append(f[:-3])
        return tuple(l)
    
    def read(self, f):
        return open(os.path.join(self._srcName, f) + '.py').read()

class MibBuilder:
    loadTexts = 0
    defaultCoreMibs = 'pysnmp.smi.mibs.instances:pysnmp.smi.mibs'
    defaultMiscMibs = 'pysnmp_mibs'
    def __init__(self):
        self.lastBuildId = self._autoName = 0L
        sources = []
        for m in string.split(
            os.environ.get('PYSNMP_MIB_PKGS', self.defaultCoreMibs), ':'
            ):
            sources.append(ZipMibSource(m).init())
        # Compatibility variable
        if os.environ.has_key('PYSNMP_MIB_DIR'):
            os.environ['PYSNMP_MIB_DIRS'] = os.environ['PYSNMP_MIB_DIR']
        if os.environ.has_key('PYSNMP_MIB_DIRS'):
            for m in string.split(os.environ['PYSNMP_MIB_DIRS'], ':'):
                sources.append(DirMibSource(m).init())
        if self.defaultMiscMibs:
            for m in string.split(self.defaultMiscMibs, ':'):
                try:
                    sources.append(ZipMibSource(m).init())
                except ImportError:
                    pass
        self.mibSymbols = {}
        self.__modSeen = {}
        self.__modPathsSeen = {}
        apply(self.setMibSources, sources)
        
    # MIB modules management

    def setMibSources(self, *mibSources):
        self.__mibSources = mibSources
        debug.logger & debug.flagBld and debug.logger('setMibPath: new MIB sources %s' % (self.__mibSources,))

    def getMibSources(self): return self.__mibSources

    # Legacy/compatibility methods
    def setMibPath(self, *mibPaths):
        apply(self.setMibSources, map(DirMibSource, mibPaths))

    def getMibPath(self):
        l = []
        for mibSource in self.getMibSources():
            if isinstance(mibSource, DirMibSource):
                l.append(mibSource.fullPath())
        return tuple(l)
        
    def loadModules(self, *modNames):
        # Build a list of available modules
        if not modNames:
            modNames = {}
            for mibSource in self.__mibSources:
                for modName in mibSource.listdir():
                    modNames[modName] = None
            modNames = modNames.keys()
        if not modNames:
            raise error.SmiError(
                'No MIB module to load at %s' % (self,)
                )
        
        for modName in modNames:
            for mibSource in self.__mibSources:
                debug.logger & debug.flagBld and debug.logger('loadModules: trying %s at %s' % (modName, mibSource))
                try:
                    modData = mibSource.read(modName)
                except IOError, why:
                    debug.logger & debug.flagBld and debug.logger('loadModules: read %s from %s failed: %s' % (modName, mibSource, why))
                    continue

                modPath = mibSource.fullPath(modName)
                
                if self.__modPathsSeen.has_key(modPath):
                    debug.logger & debug.flagBld and debug.logger('loadModules: seen %s' % modPath)
                    continue
                else:
                    self.__modPathsSeen[modPath] = 1

                debug.logger & debug.flagBld and debug.logger('loadModules: evaluating %s' % modPath)
                
                g = { 'mibBuilder': self }

                try:
                    exec(modData, g)
                except StandardError, why:
                    del self.__modPathsSeen[modPath]
                    raise error.SmiError(
                        'MIB module \"%s\" load error: %s' % (modPath, why)
                        )

                self.__modSeen[modName] = modPath

                debug.logger & debug.flagBld and debug.logger('loadModules: loaded %s' % modPath)

                break

            if not self.__modSeen.has_key(modName):
                raise error.SmiError(
                    'MIB file \"%s\" not found in search path' % (modName and modName + ".py")
                    )

        return self
                
    def unloadModules(self, *modNames):
        if not modNames:
            modNames = self.mibSymbols.keys()
        for modName in modNames:
            if not self.mibSymbols.has_key(modName):
                raise error.SmiError(
                    'No module %s at %s' % (modName, self)
                    )
            self.unexportSymbols(modName)
            del self.__modPathsSeen[self.__modSeen[modName]]
            del self.__modSeen[modName]
            
            debug.logger & debug.flagBld and debug.logger('unloadModules: ' % (modName))
            
        return self

    def importSymbols(self, modName, *symNames):
        if not modName:
            raise error.SmiError(
                'importSymbols: empty MIB module name'
            )
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
            debug.logger & debug.flagBld and debug.logger('exportSymbols: anonymous symbol %s::__pysnmp_%ld'  % (modName, self._autoName))
            mibSymbols['__pysnmp_%ld' % self._autoName] = symObj
            self._autoName = self._autoName + 1
        for symName, symObj in namedSyms.items():
            if mibSymbols.has_key(symName):
                raise error.SmiError(
                    'Symbol %s already exported at %s' % (symName, modName)
                    )

            if hasattr(symObj, 'label'):
                symName = symObj.label or symName # class
            if type(symObj) == types.InstanceType:
                symName = symObj.getLabel() or symName # class instance
            
            mibSymbols[symName] = symObj
            
            debug.logger & debug.flagBld and debug.logger('exportSymbols: symbol %s::%s' % (modName, symName))
            
        self.lastBuildId = self.lastBuildId + 1

    def unexportSymbols(self, modName, *symNames):
        if not self.mibSymbols.has_key(modName):
            raise error.SmiError(
                'No module %s at %s' % (modName, self)
                )
        mibSymbols = self.mibSymbols[modName]
        if not symNames:
            symNames = mibSymbols.keys()
        for symName in symNames:
            if not mibSymbols.has_key(symName):
                raise error.SmiError(
                    'No symbol %s::%s at %s' % (modName, symName, self)
                    )
            del mibSymbols[symName]
            
            debug.logger & debug.flagBld and debug.logger('unexportSymbols: symbol %s::%s' % (modName, symName))
            
        if not self.mibSymbols[modName]:
            del self.mibSymbols[modName]

        self.lastBuildId = self.lastBuildId + 1
            
