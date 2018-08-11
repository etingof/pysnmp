Download PySNMP
===============

.. toctree::
   :maxdepth: 2

The PySNMP software is provided under terms and conditions of BSD-style 
license, and can be freely downloaded from 
`PyPI <https://pypi.org/project/pysnmp/>`_ or
GitHub (`master branch <https://github.com/etingof/pysnmp/archive/master.zip>`_).


Besides official releases, it's advisable to try the cutting-edge
development code that could be taken from PySNMP
`source code repository <https://github.com/etingof/pysnmp>`_.
It may be less stable in regards to general operation and changes to
public interfaces, but it's first to contain fixes to recently discovered bugs.

The best way to obtain PySNMP and dependencies is to run:

.. code-block:: bash

   $ pip install pysnmp

or

.. code-block:: bash

   $ easy_install pysnmp

In case you do not have the easy_install command on your system but still 
would like to use the on-line package installation method, please install 
`setuptools <https://pypi.org/project/setuptools/>`_ package by 
downloading and running `ez_setup.pz <https://bootstrap.pypa.io/ez_setup.py>`_ bootstrap:

.. code-block:: bash

   # wget https://bootstrap.pypa.io/ez_setup.py
   # python ez_setup.py

In case you are installing PySNMP on an off-line system, the following 
packages need to be downloaded and installed for PySNMP to become 
operational:

* `pysnmp <https://pypi.org/project/pysnmp/>`_,
  SNMP engine implementation
* `pyasn1 <https://pypi.org/project/pyasn1/>`_,
  used for handling ASN.1 objects
* `pysmi <https://pypi.org/project/pysmi/>`_ for automatic
  MIB download and compilation. That helps visualizing more SNMP objects

Optional:

* `pysnmpcrypto <https://pypi.org/project/pysnmpcrypto/>`_,
  for strong SNMPv3 crypto support

The installation procedure for all the above packages is as follows 
(on UNIX-based systems):

.. code-block:: bash

   $ tar zxf package-X.X.X.tar.gz 
   $ cd package-X.X.X 
   # python setup.py install 
   # cd .. 
   # rm -rf package-X.X.X

In case of any issues, please open a `GitHub issue <https://github.com/etingof/pysnmp/issues/new>`_ so we could try to help out.


