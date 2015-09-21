 
Examples scripts
================

.. toctree::
   :maxdepth: 2

SNMP is not really simple (PySNMP implementation takes over 15K lines of
Python code), but PySNMP tries to isolate the complexities and let you 
perform typical SNMP operations in a quick and intuitive way.

PySNMP offers three groups of programming interfaces to deal with 
SNMP protocol. In the order from most consice to most detailed those 
APIs are:

#. High-level API

   .. toctree::
      :maxdepth: 2

      /examples/hlapi/asyncore/contents

#. Complete implementation of all official Standard SNMP Applications. It 
   should let you implement any SNMP operation defined in the standard. 

   This API comes in several transport varieties.

   #. Most mature and stable transport implementation is based on Python's
      bult-in asyncore module. So this API is called Native or Asyncore API.

      .. toctree::
         :maxdepth: 2

         /examples/v3arch/asyncore/contents

   #. Modern, co-routines based API takes shape of asyncio bindings 
      (Python 3.3+) or Trollius bindings (Python 2.6-3.4)

      .. toctree::
         :maxdepth: 2

         /examples/v3arch/asyncio/contents
         /examples/v3arch/trollius/contents

   #. Slightly aged, Twisted-based based API.

      .. toctree::
         :maxdepth: 2

         /examples/v3arch/twisted/contents

#. Low-level API that lets you build SNMP messages from Python 
   objects and exchange them through asyncore transport (or you could 
   write your own). These interfaces are very low-level and aimed at 
   a rather specific programming tasks.

   .. toctree::
      :maxdepth: 2

      /examples/v1arch/asyncore/contents

.. comment #. SMI subsystem is separated from SNMP protocol implementation, and
   consists of MIB files processing, MIB browsing and MIB variables
   management subsystems.

   .. toctree::
      :maxdepth: 2

      /examples/v1arch/smi/contents

Before doing cut&paste of the code below into your Python interpreter, 
make sure to install pysnmp and its dependencies by running pip or 
easy_install: ::

    # pip pysnmp

There's a public SNMP responder configured at *demo.snmplabs.com:161* to
let you run PySNMP examples scripts in a cut&paste fashion. If you 
wish to use your own SNMP Agent with these scripts, make sure to either 
configure your local snmpd and/or snmptrapd or use a valid address and 
SNMP credentials of your SNMP Agent in the examples to let them work.

If you find your PySNMP application behaving unexpectedly, try to enable 
a /more or less verbose/ built-in PySNMP debugging by adding the 
following snippet of code at the beginning of your application:

.. code-block:: python

    from pysnmp import debug

    # use specific flags or 'all' for full debugging
    debug.setLogger(debug.Debug('dsp', 'msgproc', 'secmode'))

Then run your app and watch stderr. The Debug initializer enables debugging 
for a particular PySNMP subsystem, 'all' enables full debugging. More 
specific flags are:

* io
* dsp
* msgproc
* secmod
* mibbuild
* mibview
* mibinstrum
* acl
* proxy
* app

For more details on PySNMP programming model and interfaces, please 
refer to the documentation.
