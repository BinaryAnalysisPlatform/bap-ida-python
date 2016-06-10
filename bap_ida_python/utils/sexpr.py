"""S-Expression utilities."""


def to_list(s):
    """Convert S-Expression to List."""
    assert(is_valid(s))
    sexp = [[]]
    word = ''
    in_str = False
    for c in s:
        if c == '(' and not in_str:
            sexp.append([])
        elif c == ')' and not in_str:
            if word:
                sexp[-1].append(word)
                word = ''
            temp = sexp.pop()
            sexp[-1].append(temp)
        elif c in (' ', '\n', '\t') and not in_str:
            if word:
                sexp[-1].append(word)
            word = ''
        elif c == '\"':
            in_str = not in_str
        else:
            word += c
    if word:  # Final word, if it remains
        sexp[-1].append(word)
    return sexp[0]


def from_list(l):
    """Convert List to S-Expression."""
    if isinstance(l, str):
        for special_char in (' ', '\n', '\t', '(', ')', '\"'):
            if special_char in l:
                return '\"' + l + '\"'
        return l
    return '(' + ' '.join(from_list(e) for e in l) + ')'


def is_valid(s):
    """Return True if s is a valid S-Expression."""
    in_str = False
    bb = 0
    for c in s:
        if c == '(' and not in_str:
            bb += 1
        elif c == ')' and not in_str:
            bb -= 1
            if bb < 0:
                return False
        elif c == '\"':
            in_str = not in_str
    return bb == 0


def truncate(s):
    """Truncate s to a valid S-Expression."""
    in_str = False
    bb = 0
    for i, c in enumerate(s):
        if c == '(' and not in_str:
            bb += 1
        elif c == ')' and not in_str:
            bb -= 1
            if bb == 0:
                return s[:i+1]
        elif c == '\"':
            in_str = not in_str
    raise ValueError('Insufficient close brackets in ' + repr(s))


def complete(s):
    """Add enough close brackets to s to make it a valid S-Expression."""
    in_str = False
    bb = 0
    for i, c in enumerate(s):
        if c == '(' and not in_str:
            bb += 1
        elif c == ')' and not in_str:
            bb -= 1
            if bb < 0:
                raise ValueError('Insufficient open brackets in ' + repr(s))
        elif c == '\"':
            in_str = not in_str
    return s + ')' * bb
