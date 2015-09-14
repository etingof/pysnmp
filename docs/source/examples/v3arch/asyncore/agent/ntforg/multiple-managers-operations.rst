.. toctree::
   :maxdepth: 2

Multiple managers operations
----------------------------

SNMPv3 framework is designed to allow Agents sending the same PDU
to multiple Managers over different network transports, listening at
different network addresses over different SNMP versions/credentials.

The following few examples use this facility.

.. include:: /../../examples/v3arch/asyncore/agent/ntforg/inform-multiple-protocols.py
   :start-after: """
   :end-before: """#

.. literalinclude:: /../../examples/v3arch/asyncore/agent/ntforg/inform-multiple-protocols.py
   :start-after: """#
   :language: python

:download:`Download</../../examples/v3arch/asyncore/agent/ntforg/inform-multiple-protocols.py>` script.

.. include:: /../../examples/v3arch/asyncore/agent/ntforg/trap-v2c-multiple-addresses.py
   :start-after: """
   :end-before: """#

.. literalinclude:: /../../examples/v3arch/asyncore/agent/ntforg/trap-v2c-multiple-addresses.py
   :start-after: """#
   :language: python

:download:`Download</../../examples/v3arch/asyncore/agent/ntforg/trap-v2c-multiple-addresses.py>` script.

.. include:: /../../examples/v3arch/asyncore/agent/ntforg/trap-v2c-multiple-transports.py
   :start-after: """
   :end-before: """#

.. literalinclude:: /../../examples/v3arch/asyncore/agent/ntforg/trap-v2c-multiple-transports.py
   :start-after: """#
   :language: python

:download:`Download</../../examples/v3arch/asyncore/agent/ntforg/trap-v2c-multiple-transports.py>` script.

