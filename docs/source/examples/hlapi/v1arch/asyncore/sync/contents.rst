
Synchronous SNMP (v1arch)
=========================

This chapter illustrates various uses of the synchronous high-level
programming interface to client-side SNMP entities along the lines
of `RFC1905 <https://tools.ietf.org/html/rfc1905>`_.

.. note:: The following examples involve creating Python iterator, 
          the next() call is used to invoke iterator just once.

In most examples approximate analogues of well known Net-SNMP snmp* tools
command line options are shown. That may help those readers who, by chance
are familiar with Net-SNMP tools, better understanding what the example
code does.

Here's a quick example on a simple SNMP GET by high-level API:

.. include:: /../../examples/hlapi/v1arch/asyncore/sync/manager/cmdgen/v1-get.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/v1arch/asyncore/sync/manager/cmdgen/v1-get.py
   :start-after: """#
   :language: python

.. note::

   If MIB lookup is required (e.g. when :py:class:`~pysnmp.smi.rfc1902.ObjectIdentity`,
   :py:class:`~pysnmp.smi.rfc1902.ObjectType` or :py:class:`~pysnmp.smi.rfc1902.NotificationType`
   objects being used), the `lookupMib=True` should also be passed.

The following code performs a series of SNMP GETNEXT operations
fetching a table of SNMP variables from SNMP Agent:

.. include:: /../../examples/hlapi/v1arch/asyncore/sync/manager/cmdgen/pull-whole-mib.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/v1arch/asyncore/sync/manager/cmdgen/pull-whole-mib.py
   :start-after: """#
   :language: python

More examples on Command Generator API usage follow.

.. toctree::

   /examples/hlapi/v1arch/asyncore/sync/manager/cmdgen/snmp-versions
   /examples/hlapi/v1arch/asyncore/sync/manager/cmdgen/modifying-variables
   /examples/hlapi/v1arch/asyncore/sync/manager/cmdgen/walking-operations
   /examples/hlapi/v1arch/asyncore/sync/manager/cmdgen/table-operations
   /examples/hlapi/v1arch/asyncore/sync/manager/cmdgen/mib-tweaks
   /examples/hlapi/v1arch/asyncore/sync/manager/cmdgen/transport-tweaks
   /examples/hlapi/v1arch/asyncore/sync/manager/cmdgen/advanced-topics

The following code sends SNMP TRAP:

.. include:: /../../examples/hlapi/v1arch/asyncore/sync/agent/ntforg/generic-v2c-trap.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/v1arch/asyncore/sync/agent/ntforg/generic-v2c-trap.py
   :start-after: """#
   :language: python

More examples on Notification Originator API usage follow.

.. toctree::

   /examples/hlapi/v1arch/asyncore/sync/agent/ntforg/common-notifications
   /examples/hlapi/v1arch/asyncore/sync/agent/ntforg/evaluating-notification-type

More specific SNMP operations can still be performed with PySNMP via
its Native API to Standard SNMP Applications.
