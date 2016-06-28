"""Module for reading from and writing to the bap.cfg config file."""

import os
import idaapi

cfg_dir = idaapi.idadir('cfg')
cfg_path = os.path.join(cfg_dir, 'bap.cfg')


def _read():
    if not os.path.exists(cfg_path):
        return {}
    cfg = {'default': []}
    with open(cfg_path, 'r') as f:
        current_section = 'default'
        for line in f.read().split('\n'):
            if len(line) == 0:  # Empty line
                continue
            elif line[0] == '.':  # Section
                current_section = line[1:]
                if current_section not in cfg:
                    cfg[current_section] = []
            else:
                cfg[current_section].append(line)
    return cfg


def _write(cfg):
    new_config = []
    for section in cfg:
        new_config.append('.' + section)
        for line in cfg[section]:
            new_config.append(line)
        new_config.append('')
    if not os.path.exists(cfg_dir):
        os.makedirs(cfg_dir)
    with open(cfg_path, 'w') as f:
        f.write('\n'.join(new_config))


def get(key, default=None, section='default'):
    """Get value from key:value in the config file."""
    cfg = _read()
    if section not in cfg:
        return default
    for line in cfg[section]:
        if line[0] == ';':  # Comment
            continue
        elif line.split()[0] == key:
            return line.split()[1]
    return default


def set(key, value, section='default'):
    """Set key:value in the config file."""
    cfg = _read()

    if section not in cfg:
        cfg[section] = []
    for i, line in enumerate(cfg[section]):
        if line[0] == ';':  # Comment
            continue
        elif line.split()[0] == key:
            cfg[section][i] = '{}\t{}\t; Previously: {}'.format(
                              key, value, line)
            break
    else:  # Key not previously set
        cfg[section].append('{}\t{}'.format(key, value))

    _write(cfg)
