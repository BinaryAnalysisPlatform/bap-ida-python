How to get IDA Python to work with IDA Demo
===========================================

Go to the IDAPython [binaries page](https://github.com/idapython/bin).
Download the latest `_linux.zip` file and extract it. In my case, it was `idapython-6.9.0-python2.7-linux.zip`.
Follow the instructions in its `README.txt`. 

For simplicity, I have copy pasted the relevant portions here:

```
1. Install 2.6 or 2.7 from http://www.python.org/
2. Copy the whole "python" directory to %IDADIR%
3. Copy the contents of the "plugins" directory to the %IDADIR%\plugins\
4. Copy "python.cfg" to %IDADIR%\cfg
```

In order to do step 1 correctly on a 64-bit Ubuntu 14.04, I had to run `sudo apt-get install libpython2.7:i386` and get all the libraries needed with their 32 bit versions.
Rest of the steps are quite straight forward.
BTW, `%IDADIR%` is the directory where you have IDA extracted/installed.

Now, whenever you open IDA, you will have access to IDA Python.

Note: Some of the functions like `idaapi.init_hexrays_plugin()` will obviously not work (since you don't have a decompiler in Demo), but most things should work otherwise.