#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
import os
import sys

DEFAULT_SOURCES = ['file:///usr/share/snmp/mibs', 'file:///usr/share/mibs']

if sys.platform[:3] == 'win':
    DEFAULT_DEST = os.path.join(os.path.expanduser("~"),
                               'PySNMP Configuration', 'mibs')
else:
    DEFAULT_DEST = os.path.join(os.path.expanduser("~"), '.pysnmp', 'mibs')

DEFAULT_BORROWERS = []

try:
    from pysmi.reader.url import getReadersFromUrls
    from pysmi.searcher.pypackage import PyPackageSearcher
    from pysmi.searcher.stub import StubSearcher
    from pysmi.borrower.pyfile import PyFileBorrower
    from pysmi.writer.pyfile import PyFileWriter
    from pysmi.parser.smi import parserFactory
    from pysmi.parser.dialect import smiV1Relaxed
    from pysmi.codegen.pysnmp import PySnmpCodeGen, baseMibs
    from pysmi.compiler import MibCompiler

except ImportError as exc:
    from pysnmp.smi import error


    def addMibCompilerDecorator(errorMsg):
        def addMibCompiler(mibBuilder, **kwargs):
            if not kwargs.get('ifAvailable'):
                raise error.SmiError('MIB compiler not available: %s' % errorMsg)

        return addMibCompiler


    addMibCompiler = addMibCompilerDecorator(exc)

else:

    def addMibCompiler(mibBuilder, **kwargs):
        if kwargs.get('ifNotAdded') and mibBuilder.getMibCompiler():
            return

        compiler = MibCompiler(parserFactory(**smiV1Relaxed)(),
                               PySnmpCodeGen(),
                               PyFileWriter(kwargs.get('destination') or DEFAULT_DEST))

        compiler.addSources(*getReadersFromUrls(*kwargs.get('sources') or DEFAULT_SOURCES))

        compiler.addSearchers(StubSearcher(*baseMibs))
        compiler.addSearchers(*[PyPackageSearcher(x.fullPath()) for x in mibBuilder.getMibSources()])
        compiler.addBorrowers(*[PyFileBorrower(x, genTexts=mibBuilder.loadTexts) for x in
                                getReadersFromUrls(*kwargs.get('borrowers') or DEFAULT_BORROWERS,
                                                   lowcaseMatching=False)])

        mibBuilder.setMibCompiler(
            compiler, kwargs.get('destination') or DEFAULT_DEST
        )
