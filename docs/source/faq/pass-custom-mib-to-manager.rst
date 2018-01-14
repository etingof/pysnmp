
How to pass MIB to the Manager
------------------------------

Q. How to make use of random MIBs at my Manager application?

A. Starting from PySNMP 4.3.x, plain-text (ASN.1) MIBs can be
   automatically parsed into PySNMP form by the
   `PySMI <http://snmplabs.com/pysmi/>`_ tool.  PySNMP will call PySMI
   automatically, parsed PySNMP MIB will be cached in
   $HOME/.pysnmp/mibs/ (default location).

   MIB compiler could be configured to search for plain-text
   MIBs at multiple local and remote locations. As for remote
   MIB repos, you are welcome to use our collection of ASN.1
   MIB files at
   `http://mibs.snmplabs.com/asn1/ <http://mibs.snmplabs.com/asn1/>`_
   as shown below.

.. literalinclude:: /../../examples/hlapi/asyncore/sync/manager/cmdgen/custom-asn1-mib-search-path.py
   :start-after: """#
   :language: python

.. code:
    :language: python
    
    # Configure the SNMP engine with access to the
    # common Linux ASN.1 (Textual) MIB directories...
    from pysnmp import hlapi
    from pysnmp.smi import compiler
    engine = hlapi.Engine()
    builder = engine.getMibBuilder()
    compiler.addMibCompiler(builder, sources=[
        '/usr/share/snmp/mibs',
        os.path.expanduser('~/.snmp/mibs'),
        'http://mibs.snmplabs.com/asn1/@mib@',
    ])

:download:`Download</../../examples/hlapi/asyncore/sync/manager/cmdgen/custom-asn1-mib-search-path.py>` script.

Alternatively, you can invoke the
`mibdump.py <http://snmplabs.com/pysmi/mibdump.html>`_
(shipped with PySMI) by hand and this way compile plain-text MIB
into PySNMP format. Once the compiled MIBs are stored in a directory,
add the directory to your MibBuilder's MibSources.

.. code::

    builder = engine.getMibBuilder()
    # Make ./mibs available to all OIDs that are created
    # e.g. with "MIB-NAME-MIB::identifier"
    builder.addMibSources(builder_module.DirMibSource(
        os.path.join( HERE, 'mibs')
    ))

