BAP IDA Python
==============

This package provides the necessary IDAPython scripts required for
interoperatibility between BAP and IDA Pro.

Installation
------------

Copy all of the files and directories from the `plugins` directory into `$IDADIR/plugins`.

The first run of IDA after that will prompt you to provide the path to BAP (along with a default if IDA is able to automatically detect BAP). If you wish to edit the path to BAP manually later, you can edit the file `$IDADIR/cfg/bap.cfg`.
