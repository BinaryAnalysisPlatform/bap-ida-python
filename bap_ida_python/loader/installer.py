#! /usr/bin/env python
"""Loader for setting up IDA to successfully import all BAP plugins."""


def _multi_line_string_clean(s):
    s_split = s.split('\n')[1:]
    for i, c in enumerate(s_split[0]):
        if not c.isspace():
            left_space_count = i
            break
    return '\n'.join(x[left_space_count:] for x in s_split)


def get_bap_path():
    """Return path of bap executable or None."""
    from subprocess import check_output, CalledProcessError
    import os
    try:
        bap_path = check_output(['which', 'bap']).strip()
    except OSError:  # Cannot run 'which' command
        print "[!] Could not determine bap path automatically."
        print "[ ] Please enter path to bap executable (including /bap): "
        bap_path = input('  BAP Path: ').strip()
    except CalledProcessError:  # 'which' could not find 'bap'
        print "[!] Unable to locate bap. Please install it and ensure that it"
        print "        is on your path, and `bap --version` works."
        return None
    if os.path.isfile(bap_path) and bap_path.endswith('/bap'):
        return bap_path
    else:
        print "[!] Unable to locate bap at {}".format(bap_path)
        return None


def install_bap_config():
    """Install bap execution path into config for later use."""
    import sys
    from bap_ida_python.utils import bap

    bap_path = get_bap_path()
    if bap_path is None:
        print "[!] Cannot install loader without knowing bap path"
        sys.exit(1)

    print "[+] Found bap installed at", bap_path

    bap.config.set('bap_executable_path', bap_path)
    print "[+] Updated config with bap executable path"


def main():
    """Generate short script to be run inside IDA to integrate with BAP."""
    import os

    install_bap_config()

    import bap_ida_python
    bip_path = os.path.abspath(bap_ida_python.__file__)
    bip_dir = os.path.dirname(os.path.dirname(bip_path))
    print "[+] Found bap-ida-python installed at", bip_dir

    ida_loader_code = _multi_line_string_clean(
        """
        import sys
        sys.path.append({})
        from bap_ida_python.loader.plugin import bap_loader, PLUGIN_ENTRY
        """.format(repr(bip_dir))
    )

    import tempfile
    fd, filename = tempfile.mkstemp(suffix='.py', prefix='bap-')
    f = os.fdopen(fd, 'w')
    f.write(ida_loader_code)
    print "[+] Finished writing loader code to {}".format(repr(filename))

    ida_command = _multi_line_string_clean(
        """
        idc.Exec("mv {} "+idaapi.idadir('plugins')+"/plugin_loader_bap.py")
        idaapi.load_plugin("plugin_loader_bap.py")
        """.format(repr(filename))
    ).replace('\n', ';')
    print "[+] You can now install it into IDA by running the following:"
    print
    print ida_command
    print

if __name__ == '__main__':
    main()
