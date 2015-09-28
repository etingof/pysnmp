
Synchronous SNMP
================

This chapter illustrates various uses of the synchronous high-level
programming interface to some of Standard SNMP Applications, as defined in 
`RFC3413 <https://tools.ietf.org/html/rfc3413>`_.

.. note:: The following examples involve creating Python iterator, 
          the next() call is used to invoke iterator just once.

In most examples approximate analogues of well known Net-SNMP snmp* tools
command line options are shown. That may help those readers who, by chance
are familiar with Net-SNMP tools, better understanding what example code doe

Here's a quick example on a simple SNMP GET by high-level API:

.. include:: /../../examples/hlapi/asyncore/sync/manager/cmdgen/v1-get.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/asyncore/sync/manager/cmdgen/v1-get.py
   :start-after: """#
   :language: python

To make use of SNMPv3 and USM, the following code performs a series of
SNMP GETNEXT operations effectively fetching a table of SNMP variables
from SNMP Agent:

.. include:: /../../examples/hlapi/asyncore/sync/manager/cmdgen/pull-whole-mib.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/asyncore/sync/manager/cmdgen/pull-whole-mib.py
   :start-after: """#
   :language: python

More examples on Command Generator API usage follow.

.. toctree::

   /examples/hlapi/asyncore/sync/manager/cmdgen/snmp-versions
   /examples/hlapi/asyncore/sync/manager/cmdgen/modifying-variables
   /examples/hlapi/asyncore/sync/manager/cmdgen/walking-operations
   /examples/hlapi/asyncore/sync/manager/cmdgen/table-operations
   /examples/hlapi/asyncore/sync/manager/cmdgen/mib-tweaks
   /examples/hlapi/asyncore/sync/manager/cmdgen/transport-tweaks
   /examples/hlapi/asyncore/sync/manager/cmdgen/advanced-topics

Sending SNMP TRAP's and INFORM's is as easy with PySNMP library.
The following code sends SNMP TRAP:

.. include:: /../../examples/hlapi/asyncore/sync/agent/ntforg/default-v1-trap.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/asyncore/sync/agent/ntforg/default-v1-trap.py
   :start-after: """#
   :language: python

More examples on Notification Originator API usage follow.

.. toctree::

   /examples/hlapi/asyncore/sync/agent/ntforg/common-notifications
   /examples/hlapi/asyncore/sync/agent/ntforg/snmp-v1-trap-variants
   /examples/hlapi/asyncore/sync/agent/ntforg/evaluating-notification-type
   /examples/hlapi/asyncore/sync/agent/ntforg/advanced-topics

More sophisticated or less popular SNMP operations can still be performed 
with PySNMP through its Native API to Standard SNMP Applications.
