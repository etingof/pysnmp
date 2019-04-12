#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
import os
import sys
import struct
import marshal
import time
import traceback

try:
    import importlib

    try:
        PY_MAGIC_NUMBER = importlib.util.MAGIC_NUMBER
        SOURCE_SUFFIXES = importlib.machinery.SOURCE_SUFFIXES
        BYTECODE_SUFFIXES = importlib.machinery.BYTECODE_SUFFIXES

    except Exception:
        raise ImportError()

except ImportError:
    import imp

    PY_MAGIC_NUMBER = imp.get_magic()
    SOURCE_SUFFIXES = [s[0] for s in imp.get_suffixes()
                       if s[2] == imp.PY_SOURCE]
    BYTECODE_SUFFIXES = [s[0] for s in imp.get_suffixes()
                         if s[2] == imp.PY_COMPILED]

PY_SUFFIXES = SOURCE_SUFFIXES + BYTECODE_SUFFIXES

try:
    from errno import ENOENT
except ImportError:
    ENOENT = -1

from pysnmp import version as pysnmp_version
from pysnmp.smi import error
from pysnmp import debug

if sys.version_info[0] <= 2:
    import types

    classTypes = (types.ClassType, type)
else:
    classTypes = (type,)


class __AbstractMibSource(object):
    def __init__(self, srcName):
        self._srcName = srcName
        self.__inited = None
        debug.logger & debug.flagBld and debug.logger('trying %s' % self)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self._srcName)

    def _uniqNames(self, files):
        u = set()

        for f in files:
            if f.startswith('__init__.'):
                continue

            u.update(f[:-len(sfx)] for sfx in PY_SUFFIXES if f.endswith(sfx))

        return tuple(u)

    # MibSource API follows

    def fullPath(self, f='', sfx=''):
        return self._srcName + (f and (os.sep + f + sfx) or '')

    def init(self):
        if self.__inited is None:
            self.__inited = self._init()
            if self.__inited is self:
                self.__inited = True
        if self.__inited is True:
            return self

        else:
            return self.__inited

    def listdir(self):
        return self._listdir()

    def read(self, f):
        pycTime = pyTime = -1

        for pycSfx in BYTECODE_SUFFIXES:

            try:
                pycData, pycPath = self._getData(f + pycSfx, 'rb')

            except IOError:
                why = sys.exc_info()[1]
                if ENOENT == -1 or why.errno == ENOENT:
                    debug.logger & debug.flagBld and debug.logger(
                        'file %s access error: %s' % (f + pycSfx, why)
                    )

                else:
                    raise error.MibLoadError('MIB file %s access error: %s' % (f + pycSfx, why))

            else:
                if PY_MAGIC_NUMBER == pycData[:4]:
                    pycData = pycData[4:]
                    pycTime = struct.unpack('<L', pycData[:4])[0]
                    pycData = pycData[4:]
                    debug.logger & debug.flagBld and debug.logger(
                        'file %s mtime %d' % (pycPath, pycTime)
                    )
                    break

                else:
                    debug.logger & debug.flagBld and debug.logger('bad magic in %s' % pycPath)

        for pySfx in SOURCE_SUFFIXES:

            try:
                pyTime = self._getTimestamp(f + pySfx)

            except IOError:
                why = sys.exc_info()[1]
                if ENOENT == -1 or why.errno == ENOENT:
                    debug.logger & debug.flagBld and debug.logger(
                        'file %s access error: %s' % (f + pySfx, why)
                    )

                else:
                    raise error.MibLoadError('MIB file %s access error: %s' % (f + pySfx, why))

            else:
                debug.logger & debug.flagBld and debug.logger('file %s mtime %d' % (f + pySfx, pyTime))
                break

        if pycTime != -1 and pycTime >= pyTime:
            return marshal.loads(pycData), pycSfx

        if pyTime != -1:
            modData, pyPath = self._getData(f + pySfx, 'r')
            return compile(modData, pyPath, 'exec'), pyPath

        raise IOError(ENOENT, 'No suitable module found', f)

    # Interfaces for subclasses
    def _init(self):
        raise NotImplementedError()

    def _listdir(self):
        raise NotImplementedError()

    def _getTimestamp(self, f):
        raise NotImplementedError()

    def _getData(self, f, mode):
        NotImplementedError()


class ZipMibSource(__AbstractMibSource):
    def _init(self):
        try:
            p = __import__(self._srcName, globals(), locals(), ['__init__'])
            if hasattr(p, '__loader__') and hasattr(p.__loader__, '_files'):
                self.__loader = p.__loader__
                self._srcName = self._srcName.replace('.', os.sep)
                return self
            elif hasattr(p, '__file__'):
                # Dir relative to PYTHONPATH
                return DirMibSource(os.path.split(p.__file__)[0]).init()
            else:
                raise error.MibLoadError('%s access error' % (p,))

        except ImportError:
            # Dir relative to CWD
            return DirMibSource(self._srcName).init()

    @staticmethod
    def _parseDosTime(dosdate, dostime):
        t = (((dosdate >> 9) & 0x7f) + 1980,  # year
             ((dosdate >> 5) & 0x0f),  # month
             dosdate & 0x1f,  # mday
             (dostime >> 11) & 0x1f,  # hour
             (dostime >> 5) & 0x3f,  # min
             (dostime & 0x1f) * 2,  # sec
             -1,  # wday
             -1,  # yday
             -1)  # dst
        return time.mktime(t)

    def _listdir(self):
        l = []
        # noinspection PyProtectedMember
        for f in self.__loader._files.keys():
            d, f = os.path.split(f)
            if d == self._srcName:
                l.append(f)
        return tuple(self._uniqNames(l))

    def _getTimestamp(self, f):
        p = os.path.join(self._srcName, f)
        # noinspection PyProtectedMember
        if p in self.__loader._files:
            # noinspection PyProtectedMember
            return self._parseDosTime(
                self.__loader._files[p][6], self.__loader._files[p][5]
            )
        else:
            raise IOError(ENOENT, 'No such file in ZIP archive', p)

    def _getData(self, f, mode=None):
        p = os.path.join(self._srcName, f)
        try:
            return self.__loader.get_data(p), p

        except Exception:  # ZIP code seems to return all kinds of errors
            why = sys.exc_info()
            raise IOError(ENOENT, 'File or ZIP archive %s access error: %s' % (p, why[1]))


class DirMibSource(__AbstractMibSource):
    def _init(self):
        self._srcName = os.path.normpath(self._srcName)
        return self

    def _listdir(self):
        try:
            return self._uniqNames(os.listdir(self._srcName))
        except OSError:
            why = sys.exc_info()
            debug.logger & debug.flagBld and debug.logger(
                'listdir() failed for %s: %s' % (self._srcName, why[1]))
            return ()

    def _getTimestamp(self, f):
        p = os.path.join(self._srcName, f)
        try:
            return os.stat(p)[8]
        except OSError:
            raise IOError(ENOENT, 'No such file: %s' % sys.exc_info()[1], p)

    def _getData(self, f, mode):
        p = os.path.join(self._srcName, '*')
        try:
            if f in os.listdir(self._srcName):  # make FS case-sensitive
                p = os.path.join(self._srcName, f)
                fp = open(p, mode)
                data = fp.read()
                fp.close()
                return data, p

        except (IOError, OSError):
            why = sys.exc_info()
            msg = 'File or directory %s access error: %s' % (p, why[1])

        else:
            msg = 'No such file or directory: %s' % p

        raise IOError(ENOENT, msg)

class MibBuilder(object):
    defaultCoreMibs = os.pathsep.join(
        ('pysnmp.smi.mibs.instances', 'pysnmp.smi.mibs')
    )
    defaultMiscMibs = 'pysnmp_mibs'

    moduleID = 'PYSNMP_MODULE_ID'

    loadTexts = False

    # MIB modules can use this to select the features they can use
    version = pysnmp_version

    def __init__(self):
        self.lastBuildId = self._autoName = 0
        sources = []
        for ev in 'PYSNMP_MIB_PKGS', 'PYSNMP_MIB_DIRS', 'PYSNMP_MIB_DIR':
            if ev in os.environ:
                for m in os.environ[ev].split(os.pathsep):
                    sources.append(ZipMibSource(m))
        if not sources and self.defaultMiscMibs:
            for m in self.defaultMiscMibs.split(os.pathsep):
                sources.append(ZipMibSource(m))
        for m in self.defaultCoreMibs.split(os.pathsep):
            sources.insert(0, ZipMibSource(m))
        self.mibSymbols = {}
        self.__mibSources = []
        self.__modSeen = {}
        self.__modPathsSeen = set()
        self.__mibCompiler = None
        self.setMibSources(*sources)

    # MIB compiler management

    def getMibCompiler(self):
        return self.__mibCompiler

    def setMibCompiler(self, mibCompiler, destDir):
        self.addMibSources(DirMibSource(destDir))
        self.__mibCompiler = mibCompiler
        return self

    # MIB modules management

    def addMibSources(self, *mibSources):
        self.__mibSources.extend([s.init() for s in mibSources])
        debug.logger & debug.flagBld and debug.logger('addMibSources: new MIB sources %s' % (self.__mibSources,))

    def setMibSources(self, *mibSources):
        self.__mibSources = [s.init() for s in mibSources]
        debug.logger & debug.flagBld and debug.logger('setMibSources: new MIB sources %s' % (self.__mibSources,))

    def getMibSources(self):
        return tuple(self.__mibSources)

    # Legacy/compatibility methods (won't work for .eggs)
    def setMibPath(self, *mibPaths):
        self.setMibSources(*[DirMibSource(x) for x in mibPaths])

    def getMibPath(self):
        paths = ()
        for mibSource in self.getMibSources():
            if isinstance(mibSource, DirMibSource):
                paths += (mibSource.fullPath(),)
            else:
                raise error.MibLoadError(
                    'MIB source is not a plain directory: %s' % (mibSource,)
                )
        return paths

    def loadModule(self, modName, **userCtx):
        """Load and execute MIB modules as Python code"""
        for mibSource in self.__mibSources:
            debug.logger & debug.flagBld and debug.logger('loadModule: trying %s at %s' % (modName, mibSource))
            try:
                codeObj, sfx = mibSource.read(modName)

            except IOError:
                debug.logger & debug.flagBld and debug.logger(
                    'loadModule: read %s from %s failed: %s' % (modName, mibSource, sys.exc_info()[1]))
                continue

            modPath = mibSource.fullPath(modName, sfx)

            if modPath in self.__modPathsSeen:
                debug.logger & debug.flagBld and debug.logger('loadModule: seen %s' % modPath)
                break

            else:
                self.__modPathsSeen.add(modPath)

            debug.logger & debug.flagBld and debug.logger('loadModule: evaluating %s' % modPath)

            g = {'mibBuilder': self, 'userCtx': userCtx}

            try:
                exec(codeObj, g)

            except Exception:
                self.__modPathsSeen.remove(modPath)
                raise error.MibLoadError(
                    'MIB module \'%s\' load error: %s' % (modPath, traceback.format_exception(*sys.exc_info()))
                )

            self.__modSeen[modName] = modPath

            debug.logger & debug.flagBld and debug.logger('loadModule: loaded %s' % modPath)

            break

        if modName not in self.__modSeen:
            raise error.MibNotFoundError(
                'MIB file \"%s\" not found in search path (%s)' % (
                    modName and modName + ".py[co]", ', '.join([str(x) for x in self.__mibSources]))
            )

        return self

    def loadModules(self, *modNames, **userCtx):
        """Load (optionally, compiling) pysnmp MIB modules"""
        # Build a list of available modules
        if not modNames:
            modNames = {}
            for mibSource in self.__mibSources:
                for modName in mibSource.listdir():
                    modNames[modName] = None
            modNames = list(modNames)

        if not modNames:
            raise error.MibNotFoundError(
                'No MIB module to load at %s' % (self,)
            )

        for modName in modNames:
            try:
                self.loadModule(modName, **userCtx)

            except error.MibNotFoundError:
                if self.__mibCompiler:
                    debug.logger & debug.flagBld and debug.logger('loadModules: calling MIB compiler for %s' % modName)
                    status = self.__mibCompiler.compile(modName, genTexts=self.loadTexts)
                    errs = '; '.join([hasattr(x, 'error') and str(x.error) or x for x in status.values() if
                                      x in ('failed', 'missing')])
                    if errs:
                        raise error.MibNotFoundError('%s compilation error(s): %s' % (modName, errs))

                    # compilation succeeded, MIB might load now
                    self.loadModule(modName, **userCtx)

        return self

    def unloadModules(self, *modNames):
        if not modNames:
            modNames = list(self.mibSymbols.keys())
        for modName in modNames:
            if modName not in self.mibSymbols:
                raise error.MibNotFoundError(
                    'No module %s at %s' % (modName, self)
                )
            self.unexportSymbols(modName)
            self.__modPathsSeen.remove(self.__modSeen[modName])
            del self.__modSeen[modName]

            debug.logger & debug.flagBld and debug.logger('unloadModules: %s' % modName)

        return self

    def importSymbols(self, modName, *symNames, **userCtx):
        if not modName:
            raise error.SmiError(
                'importSymbols: empty MIB module name'
            )
        r = ()
        for symName in symNames:
            if modName not in self.mibSymbols:
                self.loadModules(modName, **userCtx)
            if modName not in self.mibSymbols:
                raise error.MibNotFoundError(
                    'No module %s loaded at %s' % (modName, self)
                )
            if symName not in self.mibSymbols[modName]:
                raise error.SmiError(
                    'No symbol %s::%s at %s' % (modName, symName, self)
                )
            r = r + (self.mibSymbols[modName][symName],)
        return r

    def exportSymbols(self, modName, *anonymousSyms, **namedSyms):
        if modName not in self.mibSymbols:
            self.mibSymbols[modName] = {}
        mibSymbols = self.mibSymbols[modName]

        for symObj in anonymousSyms:
            debug.logger & debug.flagBld and debug.logger(
                'exportSymbols: anonymous symbol %s::__pysnmp_%ld' % (modName, self._autoName))
            mibSymbols['__pysnmp_%ld' % self._autoName] = symObj
            self._autoName += 1
        for symName, symObj in namedSyms.items():
            if symName in mibSymbols:
                raise error.SmiError(
                    'Symbol %s already exported at %s' % (symName, modName)
                )

            if symName != self.moduleID and \
                    not isinstance(symObj, classTypes):
                label = symObj.getLabel()
                if label:
                    symName = label
                else:
                    symObj.setLabel(symName)

            mibSymbols[symName] = symObj

            debug.logger & debug.flagBld and debug.logger('exportSymbols: symbol %s::%s' % (modName, symName))

        self.lastBuildId += 1

    def unexportSymbols(self, modName, *symNames):
        if modName not in self.mibSymbols:
            raise error.SmiError('No module %s at %s' % (modName, self))
        mibSymbols = self.mibSymbols[modName]
        if not symNames:
            symNames = list(mibSymbols.keys())
        for symName in symNames:
            if symName not in mibSymbols:
                raise error.SmiError(
                    'No symbol %s::%s at %s' % (modName, symName, self)
                )
            del mibSymbols[symName]

            debug.logger & debug.flagBld and debug.logger('unexportSymbols: symbol %s::%s' % (modName, symName))

        if not self.mibSymbols[modName]:
            del self.mibSymbols[modName]

        self.lastBuildId += 1
