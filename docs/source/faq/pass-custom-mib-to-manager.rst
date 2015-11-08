
How to pass MIB to the Manager
------------------------------

Q. How to make use of random MIBs at my Manager application?

A. Starting from PySNMP 4.3.x, plain-text (ASN.1) MIBs can be
   automatically parsed into PySNMP form by the
   `PySMI <http://pysmi.sf.net>`_ tool.  PySNMP will call PySMI
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

:download:`Download</../../examples/hlapi/asyncore/sync/manager/cmdgen/custom-asn1-mib-search-path.py>` script.

Alternatively, you can invoke the
`mibdump.py <http://pysmi.sourceforge.net/user-perspective.html>`_
(shipped with PySMI) by hand and this way compile plain-text MIB
into PySNMP format.
