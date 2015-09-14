
How to pass custom MIB to the Manager
-------------------------------------

Q. How to make use of my own MIBs at my Manager application?

A. First you have to convert your plain-text MIB files into 
   pysnmp-compliant Python modules using libsmi2pysnmp tool.

   Once you have your own pysnmp MIB files at hand, you'd have to put them 
   somewhere on the filesystem (possibly bundling them with your application). 
   In order to let pysnmp engine locating and using these modules, pysnmp 
   MIB search path has to be modified.

.. code-block:: python

    from pysnmp.entity.rfc3413.oneliner import cmdgen
    from pysnmp.smi import builder

    cmdGen = cmdgen.CommandGenerator()

    mibBuilder = cmdGen.snmpEngine.msgAndPduDsp.mibInstrumController
    .mibBuilder

    mibSources = mibBuilder.getMibSources() + (
        builder.DirMibSource('/opt/my_pysnmp_mibs'),
        )

    mibBuilder.setMibSources(*mibSources)

    # Rest of CommandGenerator app would follow

   The same effect could be achieved by exporting the PYSNMP_MIB_DIRS variable 
   to process environment. Individual directories should be separated with 
   semicolons.

   In case you'd like to .egg your application or just the pysnmp MIB 
   modules, the following code would work.

.. code-block:: python

    from pysnmp.entity.rfc3413.oneliner import cmdgen
    from pysnmp.smi import builder

    cmdGen = cmdgen.CommandGenerator()

    mibBuilder = cmdGen.snmpEngine.msgAndPduDsp.mibInstrumController
    .mibBuilder

    mibSources = mibBuilder.getMibSources() + (
        builder.ZipMibSource('my_pysnmp_mibs_pkg.mibs'),
        )

    mibBuilder.setMibSources(*mibSources)

    # Rest of CommandGenerator app would follow

   The PYSNMP_MIB_PKGS environment variable holding semicolon-separated 
   list of modules could also be used for the same purpose.

   Please, note, that Python should be able to import the [.egg] package 
   holding your MIB modules (my_pysnmp_mibs_pkg in the example above). 
   That requires either putting your module into site-packages or modifying 
   Python search math (PYTHONPATH variable).

   Then in your application you could refer to your MIB by its name (when
   resolving symbolic names to OIDs) or import MIB explicitly (with 
   mibBuilder.loadModules()) so that you could resolve OIDs to symbolic 
   names (as well as other MIB information).

