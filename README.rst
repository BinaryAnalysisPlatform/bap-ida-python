BAP IDA Python
==============

This package provides the necessary IDAPython scripts required for
interoperatibility between BAP and IDA Pro.

Installation
------------

All of the requisite scripts can be installed via ``pip`` using::

    pip install git+git://github.com/BinaryAnalysisPlatform/bap-ida-python

Now all that remains is to inform IDA about where the scripts are and how to access BAP. This process is simplified greatly using the plugin installer. The installer can be run using::

    python -m bap_ida_python.loader.installer
