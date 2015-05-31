#
# Attach PySMI MIB compiler to PySNMP MIB builder and configure 
# both accordingly.
#
import os
import sys
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

except ImportError:
    from pysnmp.smi import error

    def addMibCompiler(mibBuilder,
                       sources=[],
                       destination='',
                       borrowers=[]):
        raise error.SmiError('MIB compiler not available (pysmi not installed)')

else:
    defaultSources = [ 'file:///usr/share/snmp/mibs' ]

    if sys.platform[:3] == 'win':
        defaultDest = os.path.join(os.path.expanduser("~"),
                                   'PySNMP Configuration', 'mibs')
    else:
        defaultDest = os.path.join(os.path.expanduser("~"), '.pysnmp', 'mibs')

    defaultBorrowers = []

    def addMibCompiler(mibBuilder,
                       sources=defaultSources,
                       destination=defaultDest,
                       borrowers=defaultBorrowers):

        compiler = MibCompiler(
            parserFactory(**smiV1Relaxed)(),
            PySnmpCodeGen(),
            PyFileWriter(destination)
        )

        compiler.addSources(*getReadersFromUrls(*sources))

        compiler.addSearchers(
            StubSearcher(*baseMibs) # XXX
        )
        compiler.addSearchers(
            *[ PyPackageSearcher(x.fullPath()) for x in mibBuilder.getMibSources() ]
        )

        compiler.addBorrowers(
            *[ PyFileBorrower(x) for x in getReadersFromUrls(*borrowers, **dict(originalMatching=False, lowcaseMatching=False)) ]
        )

        mibBuilder.setMibCompiler(compiler, destination)
