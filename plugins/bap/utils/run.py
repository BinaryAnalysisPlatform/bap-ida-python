"""Utilities that interact with BAP."""


def check_and_configure_bap_path():
    """
    Check if bap_executable_path is set in the config; ask user if necessary.

    Automagically also tries a bunch of strategies to find `bap` if it can,
    and uses this to populate the default path in the popup, to make the
    user's life easier. :)
    """
    from bap.utils import config
    import idaapi

    if config.get('bap_executable_path') is not None:
        return
    default_bap_path = ''

    from subprocess import check_output, CalledProcessError
    import os
    try:
        default_bap_path = check_output(['which', 'bap']).strip()
    except (OSError, CalledProcessError) as e:
        # Cannot run 'which' command  OR
        # 'which' could not find 'bap'
        try:
            default_bap_path = os.path.join(
                check_output(['opam', 'config', 'var', 'bap:bin']).strip(),
                'bap'
            )
        except OSError:
            # Cannot run 'opam'
            pass
    if not default_bap_path.endswith('bap'):
        default_bap_path = ''

    def confirm(msg):
        from idaapi import askyn_c, ASKBTN_CANCEL, ASKBTN_YES
        return askyn_c(ASKBTN_CANCEL, msg) == ASKBTN_YES

    while True:
        bap_path = idaapi.askfile_c(False, default_bap_path, 'Path to bap')
        if bap_path is None:
            if confirm('Are you sure you don\'t want to set path?'):
                return
            else:
                continue
        if not bap_path.endswith('bap'):
            if not confirm("Path does not end with bap. Confirm?"):
                continue
        if not os.path.isfile(bap_path):
            if not confirm("Path does not point to a file. Confirm?"):
                continue
        break

    config.set('bap_executable_path', bap_path)


def run_bap_with(argument_string):
    """
    Run bap with the given argument_string.

    Uses the currently open file, dumps latest symbols from IDA and runs
    BAP with the argument_string

    Also updates the 'BAP View'
    """
    from bap.plugins.bap_view import BAP_View
    from bap.utils import config
    import ida
    import idc
    import tempfile

    check_and_configure_bap_path()
    bap_executable_path = config.get('bap_executable_path')
    if bap_executable_path is None:
        return  # The user REALLY doesn't want us to run it

    args = {
        'bap_executable_path': bap_executable_path,
        'bap_output_file': tempfile.mkstemp(suffix='.out',
                                            prefix='ida-bap-')[1],
        'input_file_path': idc.GetInputFilePath(),
        'symbol_file_location': tempfile.mkstemp(suffix='.sym',
                                                 prefix='ida-bap-')[1],
        'header_path': tempfile.mkstemp(suffix='.h', prefix='ida-bap-')[1],
        'remaining_args': argument_string
    }

    ida.dump_symbol_info(args['symbol_file_location'])

    #TODO Dump header info

    idc.Exec(
        "\
        \"{bap_executable_path}\" \
        --api-add=c:\"{header_path}\" \
        ".format(**args)
    )

    command = (
        "\
        \"{bap_executable_path}\" \"{input_file_path}\" \
        --read-symbols-from=\"{symbol_file_location}\" --symbolizer=file \
        {remaining_args} \
        -d > \"{bap_output_file}\" 2>&1 \
        ".format(**args)
    )

    idc.Exec(command)

    with open(args['bap_output_file'], 'r') as f:
        BAP_View.update(
            "BAP execution string\n" +
            "--------------------\n" +
            "\n" +
            '\n    --'.join(('bap'+argument_string).split('--')) +
            "\n" +
            "\n" +
            "Output\n" +
            "------\n" +
            "\n" +
            f.read()
        )

    # Force close BAP View
    # This forces the user to re-open the new view if needed
    # This "hack" is needed since IDA decides to give a different BAP_View
    #   class here, than the cls parameter it sends to BAP_View
    # TODO: Fix this
    import idaapi
    tf = idaapi.find_tform("BAP View")
    if tf:
        idaapi.close_tform(tf, 0)

    # Do a cleanup of all the temporary files generated/added
    idc.Exec(
        "\
        \"{bap_executable_path}\" \
        --api-remove=c:\"{header_path}\" \
        ".format(**args)
    )
    idc.Exec(
        "\
        rm -f \
            \"{symbol_file_location}\" \
            \"{header_path}\" \
            \"{bap_output_file}\" \
        ".format(**args)
    )
