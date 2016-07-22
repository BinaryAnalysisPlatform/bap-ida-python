"""
BAP Comment.

A BAP Comment is an S-Expression which is of the form (BAP ...)

This module defines commonly used utility functions to interact with
BAP Comments.
"""


def get_bap_comment(comm):
    """
    Get '(BAP )' style comment from given string.

    Returns tuple (BAP_dict, start_loc, end_loc)
        BAP_dict: The '(BAP )' style comment
        start_loc: comm[:start_loc] was before the BAP comment
        end_loc: comm[end_loc:] was after the BAP comment
    """
    if '(BAP ' in comm:
        start_loc = comm.index('(BAP ')
        bracket_count = 0
        in_str = False
        for i in range(start_loc, len(comm)):
            if comm[i] == '(' and not in_str:
                bracket_count += 1
            elif comm[i] == ')' and not in_str:
                bracket_count -= 1
                if bracket_count == 0:
                    end_loc = i + 1
                    BAP_dict = comm[start_loc:end_loc]
                    break
            elif comm[i] == '\"':
                in_str = not in_str
        else:
            # Invalid bracketing.
            # Someone messed up the dict.
            # Correct by inserting enough close brackets.
            end_loc = len(comm)
            BAP_dict = comm[start_loc:end_loc] + (')' * bracket_count)
    else:
        start_loc = len(comm)
        end_loc = len(comm)
        BAP_dict = '(BAP )'

    return (BAP_dict, start_loc, end_loc)


def get_bap_list(BAP_dict):
    """Return a list containing all the values in the BAP comment."""
    import sexpr
    assert(BAP_dict[:5] == '(BAP ')
    assert(sexpr.is_valid(BAP_dict))
    outer_removed = BAP_dict[5:-1]  # Remove outermost '(BAP', ')'
    return sexpr.to_list(outer_removed)


def add_to_comment_string(comm, key, value):
    """Add key:value to comm string."""
    import sexpr

    BAP_dict, start_loc, end_loc = get_bap_comment(comm)

    if value == '()':
        kv = ['BAP', [key]]  # Make unit tags easier to read
    else:
        kv = ['BAP', [key, value]]

    for e in get_bap_list(BAP_dict):
        if isinstance(e, list) and len(e) <= 2:
            # It is of the '(k v)' or '(t)' type
            if e[0] != key:  # Don't append if same as required key
                kv.append(e)
        else:
            kv.append(e)

    return comm[:start_loc] + sexpr.from_list(kv) + comm[end_loc:]


def get_value(comm, key, default=None):
    """Get value from key:value pair in comm string."""
    BAP_dict, _, _ = get_bap_comment(comm)

    for e in get_bap_list(BAP_dict):
        if isinstance(e, list) and len(e) <= 2:
            # It is of the '(k v)' or '(t)' type
            if e[0] == key:
                try:
                    return e[1]
                except IndexError:
                    return True
    return default
