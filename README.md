BAP IDA Python
==============

This package provides the necessary IDAPython scripts required for
interoperatibility between BAP and IDA Pro. It also provides many useful feature additions to IDA, by leveraging power from BAP.

Features
--------

### Taint Propagation

By choosing a taint source and hitting either `Ctrl+A` (for tainting register) or `Ctrl+Shift+A` (for tainting pointer), one can easily see how taint propagates through the code, in both disassembly and decompilation views.

#### In Text/Graph View
![taint](docs/taint.png)

#### In Pseudocode View
![taint-decompiler](docs/taint-decompiler.png)

### BIR Attribute Tagging, with arbitrary BAP plugins

BAP has the ability to tag a lot of possible attributes to instructions. These BIR attributes can be tagged automatically as comments in IDA, by running arbitrary plugins in BAP. Just hit `Ctrl+S`.

Here's an example of output for Saluki showing that a certain malloc is unchecked (pointing to a potential vulnerability).

Clearing all BAP comments (without affecting your own personal comments in IDA) can be done by pressing `Ctrl+Shift+S`.

#### In Text/Graph View
![bir-attr-saluki](docs/bir-attr-saluki.png)

#### In Pseudocode View
![bir-attr-saluki-decompiler](docs/bir-attr-saluki-decompiler.png)

### BAP View

Sometimes, you just wish to see the BAP output of the command you just ran to generate BIR attributes (or for the taints), and you can do this in IDA by hitting `Ctrl+Alt+Shift+S` to see the command the BAP ran, along with its output. Do note that this also shows bir output from bap.

![bap-view](docs/bap-view.png)

### Symbol and Type Information

Whenever possible, `bap-ida-python` passes along the latest symbol and type information from IDA (including changes you might have made manually), so as to aid better and more accurate analysis in BAP. For example, let's say you recognize that a function is a malloc in a stripped binary, by just using IDA's rename feature (Keybinding: `N`), you can inform BAP of this change during the next run of, say, saluki, without needing to do anything extra. It works automagically!

Installation
------------

Copy all of the files and directories from the `plugins` directory into `$IDADIR/plugins`.

The first run of IDA after that will prompt you to provide the path to BAP (along with a default if IDA is able to automatically detect BAP). If you wish to edit the path to BAP manually later, you can edit the file `$IDADIR/cfg/bap.cfg`.

#### Opam?

It is usually much easier to install through opam if you have already followed all the installation steps in the [bap repository](https://github.com/BinaryAnalysisPlatform/bap). Just run:

```
opam install bap-ida-python
```

#### IDA Demo?

You can also use parts of the functionality (i.e. most of everything except for the decompiler outputs, and batch processing from bap) with IDA Free/Demo. However, you would need to install IDAPython. See [here](docs/IDAPython_on_IDADemo.md) for what one of our users reported to work.