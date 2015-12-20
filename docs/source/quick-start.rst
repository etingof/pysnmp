
Quick start
===========

.. toctree::
   :maxdepth: 2

Once you downloaded and installed PySNMP library on your Linux/Windows/OS X
system, you should be able to solve the very basic SNMP task right from 
your Python prompt - fetch some data from a remote SNMP Agent (you'd need 
at least version 4.3.0 to run code from this page).

Fetch SNMP variable
-------------------

So just cut&paste the following code right into your Python prompt. The 
code will performs SNMP GET operation for a sysDescr.0 object at a 
publically available SNMP Command Responder at
`demo.snmplabs.com <http://snmpsim.sourceforge.net/public-snmp-simulator.html>`_:

.. literalinclude:: /../../examples/hlapi/asyncore/sync/manager/cmdgen/v1-get.py
   :start-after: """#
   :language: python

:download:`Download</../../examples/hlapi/asyncore/sync/manager/cmdgen/v1-get.py>` script.

If everything works as it should you will get:

.. code-block:: python

   ...
   SNMPv2-MIB::sysDescr."0" = SunOS zeus.snmplabs.com 4.1.3_U1 1 sun4m
   >>> 

on your console.

Send SNMP TRAP
--------------

To send a trivial TRAP message to our hosted Notification Receiver at
`demo.snmplabs.com <http://snmpsim.sourceforge.net/public-snmp-simulator.html>`_
, just cut&paste the following code into your interactive Python session:

.. literalinclude:: /../../examples/hlapi/asyncore/sync/agent/ntforg/default-v1-trap.py
   :start-after: """#
   :language: python

:download:`Download</../../examples/hlapi/asyncore/sync/agent/ntforg/default-v1-trap.py>` script.

Many ASN.1 MIB files could be downloaded from
`mibs.snmplabs.com <http://mibs.snmplabs.com/asn1/>`_ or PySNMP could
be :doc:`configured <docs/api-reference>` to download them automatically.

For more sophisticated examples and use cases please refer to
:doc:`examples <examples/contents>` and :doc:`library reference <docs/api-reference>`
pages.
