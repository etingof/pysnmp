
Quick start
===========

.. toctree::
   :maxdepth: 2

Once you downloaded and installed PySNMP library on your Linux/Windows/OS-X
system, you should be able to solve the very basic SNMP task right from 
your Python prompt - fetch some data from a remote SNMP Agent (you'd need 
at least version 4.3.0 to run code from this page).

Fetch SNMP variable
-------------------

So just cut&paste the following code right into your Python prompt. The 
code will performs SNMP GET operation for a sysDescr.0 object at a 
publically available SNMP Agent at **demo.snmplabs.com**:

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

To send a trivial TRAP message to your local Notification Receiver
just cut&paste the following code into your interactive Python session:

.. literalinclude:: /../../examples/hlapi/asyncore/sync/agent/ntforg/default-v1-trap.py
   :start-after: """#
   :language: python

:download:`Download</../../examples/hlapi/asyncore/sync/agent/ntforg/default-v1-trap.py>` script.

For more sophisticated examples and use cases please refer to
:doc:`examples <examples/contents>` and :doc:`library reference <docs/api-reference>`
pages.
