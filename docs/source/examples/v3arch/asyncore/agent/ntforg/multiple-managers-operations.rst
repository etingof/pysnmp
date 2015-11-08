.. toctree::
   :maxdepth: 2

Multiple managers operations
----------------------------

SNMPv3 framework is designed to allow Agents sending the same PDU
to multiple Managers over different network transports, listening at
different network addresses over different SNMP versions/credentials.

The following few examples use this facility.

.. include:: /../../examples/v3arch/asyncore/agent/ntforg/send-inform-to-multiple-managers.py
   :start-after: """
   :end-before: """#

.. literalinclude:: /../../examples/v3arch/asyncore/agent/ntforg/send-inform-to-multiple-managers.py
   :start-after: """#
   :language: python

:download:`Download</../../examples/v3arch/asyncore/agent/ntforg/send-inform-to-multiple-managers.py>` script.

.. include:: /../../examples/v3arch/asyncore/agent/ntforg/send-trap-to-multiple-managers.py
   :start-after: """
   :end-before: """#

.. literalinclude:: /../../examples/v3arch/asyncore/agent/ntforg/send-trap-to-multiple-managers.py
   :start-after: """#
   :language: python

:download:`Download</../../examples/v3arch/asyncore/agent/ntforg/send-trap-to-multiple-managers.py>` script.

.. include:: /../../examples/v3arch/asyncore/agent/ntforg/multiple-different-notifications-at-once.py
   :start-after: """
   :end-before: """#

.. literalinclude:: /../../examples/v3arch/asyncore/agent/ntforg/multiple-different-notifications-at-once.py
   :start-after: """#
   :language: python

:download:`Download</../../examples/v3arch/asyncore/agent/ntforg/multiple-different-notifications-at-once.py>` script.


See also: :doc:`library reference </docs/api-reference>`.
