"""Module for reading from and writing to the bap.cfg config file."""

import os
import idaapi  # pylint: disable=import-error

CFG_DIR = idaapi.idadir('cfg')
CFG_PATH = os.path.join(CFG_DIR, 'bap.cfg')


def _read():
    "parse the config file"
    if not os.path.exists(CFG_PATH):
        return {}
    cfg = {'default': []}
    with open(CFG_PATH, 'r') as src:
        current_section = 'default'
        for line in src.read().split('\n'):
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
    "dump config into the file"
    new_config = []
    for section in cfg:
        new_config.append('.' + section)
        for line in cfg[section]:
            new_config.append(line)
        new_config.append('')
    if not os.path.exists(CFG_DIR):
        os.makedirs(CFG_DIR)
    with open(CFG_PATH, 'w') as out:
        out.write('\n'.join(new_config))


def get(path, default=None):
    """Get value from key:value in the config file."""
    key = Key(path)
    cfg = _read()
    if key.section not in cfg:
        return default
    for line in cfg[key.section]:
        if line[0] == ';':  # Comment
            continue
        elif line.split()[0] == key.value:
            return line.split()[1]
    return default


def is_set(key):
    """returns True if the value is set,
    i.e., if it is `1`, `true` or `yes`.
    returns False, if key is not present in the dictionary,
    or has any other value.
    """
    return get(key, default='0').lower() in ('1', 'true', 'yes')


def set(path, value):  # pylint: disable=redefined-builtin
    """Set key:value in the config file."""
    cfg = _read()
    key = Key(path)

    if key.section not in cfg:
        cfg[key.section] = []
    for i, line in enumerate(cfg[key.section]):
        if line[0] == ';':  # Comment
            continue
        elif line.split()[0] == key.value:
            cfg[key.section][i] = '{}\t{}\t; Previously: {}'.format(
                              key.value, value, line)
            break
    else:  # Key not previously set
        cfg[key.section].append('{}\t{}'.format(key.value, value))

    _write(cfg)


class Key(object):  # pylint: disable=too-few-public-methods
    "Configuration key"
    def __init__(self, path):
        elts = path.split('.')
        if len(elts) > 2:
            raise InvalidKey(path)
        simple = len(elts) == 1
        self.section = 'default' if simple else elts[0]
        self.value = elts[0] if simple else elts[1]


class InvalidKey(Exception):
    "Raised when the key is badly formated"
    def __init__(self, path):
        super(InvalidKey, self).__init__()
        self.path = path

    def __str__(self):
        return 'Invalid key syntax. \
        Expected `<key>` or `<section>.<key>`, got {0}'.format(
            self.path)
