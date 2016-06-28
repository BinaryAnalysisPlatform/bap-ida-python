"""Module for reading from and writing to the bap.cfg config file."""

import os
import idaapi

cfg_dir = idaapi.idadir('cfg')
cfg_path = os.path.join(cfg_dir, 'bap.cfg')


def get(key, default=None, section='default'):
    """Get value from key:value in the config file."""
    from bap.utils import bap_comment
    if not os.path.exists(cfg_path):
        return default
    with open(cfg_path, 'r') as f:
        current_section = 'default'
        for line in f.read().split('\n'):
            if len(line) == 0:  # Empty line
                continue
            elif line[0] == ';':  # Comment
                continue
            elif line[0] == '.':  # Section
                current_section = line[1:]
            elif section != current_section:
                continue
            elif line.split()[0] == key:
                return line.split()[1]
    return default


def set(key, value, section='default'):
    """Set key:value in the config file."""
    try:
        with open(cfg_path, 'r') as f:
            s = f.read()
    except IOError:
        s = ''

    is_set = False
    new_config = []
    current_section = None
    for line in s.split('\n'):
        if len(line) == 0:  # Empty line
            new_config.append(line)
            continue
        elif current_section is None and line[0] not in ('.', ';'):
            new_config.append('.default')
            current_section = 'default'
        if line[0] == ';':  # Comment
            pass
        elif line[0] == '.':  # Section
            current_section = line[1:]
        elif section != current_section:
            new_config.append(line)
            continue
        elif line.split()[0] == key:
            line = '{}\t{}\t; Previously: {}'.format(key, value, line)
            is_set = True
        new_config.append(line)
    if not is_set:
        if section != current_section:
            new_config.append('.' + section)
            current_section = section
        new_config.append('{}\t{}'.format(key, value))

    if not os.path.exists(cfg_dir):
        os.makedirs(cfg_dir)
    with open(cfg_path, 'w') as f:
        f.write('\n'.join(new_config))
