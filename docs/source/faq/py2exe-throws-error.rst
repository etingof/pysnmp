
My py2exe app can't find MIBs
-----------------------------

Q. I packed my pysnmp-based application with py2exe. When I run my app,
   it throws a traceback like this:

.. code-block:: bash

File "pysnmp\entity\rfc3413\oneliner\cmdgen.pyc", line 116, in __init__
File "pysnmp\entity\engine.pyc", line 16, in __init__
File "pysnmp\proto\rfc3412.pyc", line 16, in __init__
File "pysnmp\smi\builder.pyc", line 143, in __init__
File "pysnmp\smi\builder.pyc", line 35, in init
File "pysnmp\smi\builder.pyc", line 80, in _init
ImportError: No module named mibs.instances

   PySNMP claims itself to be py2exe-friendly. How to make it working?

A. You have to list pysnmp MIB directories explicitly at your app's 
   setup.py so that py2exe would include them into the binary.

.. code-block:: python

    from distutils.core import setup
    import sys

    options = {}
           
    if "py2exe" in sys.argv:
      import py2exe
      # fix executables
      options['console'] = ['myapp.py']
      # add files not found my modulefinder
      options['options'] = {
        'py2exe': {
          'includes': [
            'pysnmp.smi.mibs.*',
            'pysnmp.smi.mibs.instances.*'
          ]
        }
      }

    setup(**options)

