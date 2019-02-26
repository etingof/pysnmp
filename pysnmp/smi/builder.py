#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
import imp
import marshal
import os
import struct
import sys
import time
import traceback

try:
    from errno import ENOENT

except ImportError:
    ENOENT = -1

if sys.version_info[0] <= 2:
    import types

    classTypes = (types.ClassType, type)
else:
    classTypes = (type,)

from pysnmp import __version__ as pysnmp_version
from pysnmp.smi import error
from pysnmp import debug


class __AbstractMibSource(object):
    def __init__(self, srcName):
        self._srcName = srcName
        self._magic = imp.get_magic()
        self._sfx = {}
        self._inited = None

        for sfx, mode, typ in imp.get_suffixes():
            if typ not in self._sfx:
                self._sfx[typ] = []

            self._sfx[typ].append((sfx, len(sfx), mode))

        debug.logger & debug.FLAG_BLD and debug.logger(
            'trying %s' % self)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self._srcName)

    def _uniqNames(self, files):
        u = set()

        for f in files:
            if f.startswith('__init__.'):
                continue

            for typ in (imp.PY_SOURCE, imp.PY_COMPILED):
                for sfx, sfxLen, mode in self._sfx[typ]:
                    if f[-sfxLen:] == sfx:
                        u.add(f[:-sfxLen])
        return tuple(u)

    # MibSource API follows

    def fullPath(self, f='', sfx=''):
        if f:
            return os.path.join(self._srcName, f) + sfx

        return self._srcName

    def init(self):
        if self._inited is None:
            self._inited = self._init()

            if self._inited is self:
                self._inited = True

        if self._inited is True:
            return self

        else:
            return self._inited

    def listdir(self):
        return self._listdir()

    def read(self, f):
        pycTime = pyTime = -1

        for pycSfx, pycSfxLen, pycMode in self._sfx[imp.PY_COMPILED]:

            pycFile = f + pycSfx

            try:
                pycData, pycPath = self._getData(pycFile, pycMode)

            except IOError as exc:
                if ENOENT == -1 or exc.errno == ENOENT:
                    debug.logger & debug.FLAG_BLD and debug.logger(
                        'file %s access error: %s' % (pycFile, exc))

                else:
                    raise error.MibLoadError(
                        'MIB file %s access error: %s' % (pycFile, exc))

            else:
                if self._magic == pycData[:4]:
                    pycData = pycData[4:]
                    pycTime = struct.unpack('<L', pycData[:4])[0]
                    pycData = pycData[4:]

                    debug.logger & debug.FLAG_BLD and debug.logger(
                        'file %s mtime %d' % (pycPath, pycTime))

                    break

                else:
                    debug.logger & debug.FLAG_BLD and debug.logger(
                        'bad magic in %s' % pycPath)

        for pySfx, pySfxLen, pyMode in self._sfx[imp.PY_SOURCE]:
            pyFile = f + pySfx

            try:
                pyTime = self._getTimestamp(pyFile)

            except IOError as exc:
                if ENOENT == -1 or exc.errno == ENOENT:
                    debug.logger & debug.FLAG_BLD and debug.logger(
                        'file %s access error: %s' % (pyFile, exc))

                else:
                    raise error.MibLoadError(
                        'MIB file %s access error: %s' % (pyFile, exc))

            else:
                debug.logger & debug.FLAG_BLD and debug.logger(
                    'file %s mtime %d' % (pyFile, pyTime))
                break

        if pycTime != -1 and pycTime >= pyTime:
            return marshal.loads(pycData), pycSfx

        if pyTime != -1:
            modData, pyPath = self._getData(pyFile, pyMode)
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
            mod = __import__(
                self._srcName, globals(), locals(), ['__init__'])

            if (hasattr(mod, '__loader__') and
                    hasattr(mod.__loader__, '_files')):
                self.__loader = mod.__loader__
                self._srcName = self._srcName.replace('.', os.sep)
                return self

            elif hasattr(mod, '__file__'):
                # Dir relative to PYTHONPATH
                return DirMibSource(os.path.split(mod.__file__)[0]).init()

            else:
                raise error.MibLoadError('%s access error' % (mod,))

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
        dirs = []

        # noinspection PyProtectedMember
        for path in self.__loader._files:
            dr, fl = os.path.split(path)
            if dr == self._srcName:
                dirs.append(fl)

        return tuple(self._uniqNames(dirs))

    def _getTimestamp(self, f):
        path = os.path.join(self._srcName, f)

        # noinspection PyProtectedMember
        if path in self.__loader._files:
            # noinspection PyProtectedMember
            return self._parseDosTime(
                self.__loader._files[path][6], self.__loader._files[path][5]
            )

        else:
            raise IOError(ENOENT, 'No such file in ZIP archive', path)

    def _getData(self, f, mode=None):
        path = os.path.join(self._srcName, f)

        try:
            return self.__loader.get_data(path), path

        # ZIP code seems to return all kinds of errors
        except Exception as exc:
            raise IOError(
                ENOENT, 'File or ZIP archive %s access '
                        'error: %s' % (path, exc))


class DirMibSource(__AbstractMibSource):
    def _init(self):
        self._srcName = os.path.normpath(self._srcName)
        return self

    def _listdir(self):
        try:
            return self._uniqNames(os.listdir(self._srcName))

        except OSError as exc:
            debug.logger & debug.FLAG_BLD and debug.logger(
                'listdir() failed for %s: %s' % (self._srcName, exc))
            return ()

    def _getTimestamp(self, f):
        path = os.path.join(self._srcName, f)
        try:
            return os.stat(path)[8]
        except OSError as exc:
            raise IOError(ENOENT, 'No such file: %s' % exc, path)

    def _getData(self, fl, mode):
        path = os.path.join(self._srcName, '*')

        try:
            if fl in os.listdir(self._srcName):  # make FS case-sensitive
                path = os.path.join(self._srcName, fl)
                fp = open(path, mode)
                data = fp.read()
                fp.close()
                return data, path

        except (IOError, OSError) as exc:
            msg = 'File or directory %s access error: %s' % (path, exc)

        else:
            msg = 'No such file or directory: %s' % path

        raise IOError(ENOENT, msg)


class MibBuilder(object):
    DEFAULT_CORE_MIBS = os.pathsep.join(
        ('pysnmp.smi.mibs.instances', 'pysnmp.smi.mibs')
    )

    DEFAULT_MISC_MIBS = 'pysnmp_mibs'

    moduleID = 'PYSNMP_MODULE_ID'

    loadTexts = False

    # MIB modules can use this to select the features they can use
    version = tuple([int(x) for x in pysnmp_version.split('.')])

    def __init__(self):
        self.lastBuildId = self._autoName = 0

        sources = []

        for ev in 'PYSNMP_MIB_PKGS', 'PYSNMP_MIB_DIRS', 'PYSNMP_MIB_DIR':
            if ev in os.environ:
                for m in os.environ[ev].split(os.pathsep):
                    sources.append(ZipMibSource(m))

        if not sources and self.DEFAULT_MISC_MIBS:
            for m in self.DEFAULT_MISC_MIBS.split(os.pathsep):
                sources.append(ZipMibSource(m))

        for m in self.DEFAULT_CORE_MIBS.split(os.pathsep):
            sources.insert(0, ZipMibSource(m))

        self.mibSymbols = {}
        self._mibSources = []
        self._modSeen = {}
        self._modPathsSeen = set()
        self._mibCompiler = None

        self.setMibSources(*sources)

    # MIB compiler management

    def getMibCompiler(self):
        return self._mibCompiler

    def setMibCompiler(self, mibCompiler, destDir):
        self.addMibSources(DirMibSource(destDir))
        self._mibCompiler = mibCompiler
        return self

    # MIB modules management

    def addMibSources(self, *mibSources):
        self._mibSources.extend([s.init() for s in mibSources])

        debug.logger & debug.FLAG_BLD and debug.logger(
            'addMibSources: new MIB sources %s' % (self._mibSources,))

    def setMibSources(self, *mibSources):
        self._mibSources = [s.init() for s in mibSources]

        debug.logger & debug.FLAG_BLD and debug.logger(
            'setMibSources: new MIB sources %s' % (self._mibSources,))

    def getMibSources(self):
        return tuple(self._mibSources)

    def loadModule(self, modName, **userCtx):
        """Load and execute MIB modules as Python code"""
        for mibSource in self._mibSources:
            debug.logger & debug.FLAG_BLD and debug.logger(
                'loadModule: trying %s at %s' % (modName, mibSource))

            try:
                codeObj, sfx = mibSource.read(modName)

            except IOError as exc:
                debug.logger & debug.FLAG_BLD and debug.logger(
                    'loadModule: read %s from %s failed: '
                    '%s' % (modName, mibSource, exc))
                continue

            modPath = mibSource.fullPath(modName, sfx)

            if modPath in self._modPathsSeen:
                debug.logger & debug.FLAG_BLD and debug.logger(
                    'loadModule: seen %s' % modPath)
                break

            else:
                self._modPathsSeen.add(modPath)

            debug.logger & debug.FLAG_BLD and debug.logger(
                'loadModule: evaluating %s' % modPath)

            g = {'mibBuilder': self,
                 'userCtx': userCtx}

            try:
                exec(codeObj, g)

            except Exception:
                self._modPathsSeen.remove(modPath)
                raise error.MibLoadError(
                    'MIB module "%s" load error: '
                    '%s' % (modPath, traceback.format_exception(*sys.exc_info())))

            self._modSeen[modName] = modPath

            debug.logger & debug.FLAG_BLD and debug.logger(
                'loadModule: loaded %s' % modPath)

            break

        if modName not in self._modSeen:
            raise error.MibNotFoundError(
                'MIB file "%s" not found in search path '
                '(%s)' % (modName and modName + ".py[co]", ', '.join(
                    [str(x) for x in self._mibSources])))

        return self

    def loadModules(self, *modNames, **userCtx):
        """Load (optionally, compiling) pysnmp MIB modules"""
        # Build a list of available modules
        if not modNames:
            modNames = {}

            for mibSource in self._mibSources:
                for modName in mibSource.listdir():
                    modNames[modName] = None

            modNames = list(modNames)

        if not modNames:
            raise error.MibNotFoundError(
                'No MIB module to load at %s' % (self,))

        for modName in modNames:
            try:
                self.loadModule(modName, **userCtx)

            except error.MibNotFoundError:
                if self._mibCompiler:
                    debug.logger & debug.FLAG_BLD and debug.logger(
                        'loadModules: calling MIB compiler for %s' % modName)

                    status = self._mibCompiler.compile(modName, genTexts=self.loadTexts)

                    errs = '; '.join(
                        hasattr(x, 'error') and str(x.error) or x
                        for x in status.values()
                        if x in ('failed', 'missing'))

                    if errs:
                        raise error.MibNotFoundError(
                            '%s compilation error(s): %s' % (modName, errs))

                    # compilation succeeded, MIB might load now
                    self.loadModule(modName, **userCtx)

        return self

    def unloadModules(self, *modNames):
        if not modNames:
            modNames = list(self.mibSymbols)

        for modName in modNames:
            if modName not in self.mibSymbols:
                raise error.MibNotFoundError(
                    'No module %s at %s' % (modName, self))

            self.unexportSymbols(modName)

            self._modPathsSeen.remove(self._modSeen[modName])

            del self._modSeen[modName]

            debug.logger & debug.FLAG_BLD and debug.logger(
                'unloadModules: %s' % modName)

        return self

    def importSymbols(self, modName, *symNames, **userCtx):
        if not modName:
            raise error.SmiError(
                'importSymbols: empty MIB module name')

        symbols = []

        for symName in symNames:
            if modName not in self.mibSymbols:
                self.loadModules(modName, **userCtx)

            if modName not in self.mibSymbols:
                raise error.MibNotFoundError(
                    'No module %s loaded at %s' % (modName, self))

            if symName not in self.mibSymbols[modName]:
                raise error.SmiError(
                    'No symbol %s::%s at %s' % (modName, symName, self))

            symbols.append(self.mibSymbols[modName][symName])

        return symbols

    def exportSymbols(self, modName, *anonymousSyms, **namedSyms):
        if modName not in self.mibSymbols:
            self.mibSymbols[modName] = {}

        mibSymbols = self.mibSymbols[modName]

        for symObj in anonymousSyms:
            debug.logger & debug.FLAG_BLD and debug.logger(
                'exportSymbols: anonymous symbol %s::'
                '__pysnmp_%ld' % (modName, self._autoName))

            mibSymbols['__pysnmp_%ld' % self._autoName] = symObj

            self._autoName += 1

        for symName, symObj in namedSyms.items():
            if symName in mibSymbols:
                raise error.SmiError(
                    'Symbol %s already exported at %s' % (symName, modName))

            if (symName != self.moduleID and
                    not isinstance(symObj, classTypes)):

                label = symObj.getLabel()

                if label:
                    symName = label

                else:
                    symObj.setLabel(symName)

            mibSymbols[symName] = symObj

            debug.logger & debug.FLAG_BLD and debug.logger(
                'exportSymbols: symbol %s::%s' % (modName, symName))

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
                    'No symbol %s::%s at %s' % (modName, symName, self))

            del mibSymbols[symName]

            debug.logger & debug.FLAG_BLD and debug.logger(
                'unexportSymbols: symbol %s::%s' % (modName, symName))

        if not self.mibSymbols[modName]:
            del self.mibSymbols[modName]

        self.lastBuildId += 1
