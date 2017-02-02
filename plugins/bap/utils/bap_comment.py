"""BAP Comment.

We use comments to annotate code in IDA with the semantic information
extracted from BAP analyses. The comments are machine-readable, and a
simple syntax is used, to make the parser robust and comments human
readable. We will define the syntax formally later, but we will start
with an example:

    BAP: saluki-sat,saluki-unsat, beagle-strings="hello, world",nice

Basically, the comment string includes an arbitrary amount of
key=value pairs. If a value contains whitespaces, punctuation or any
non-word character, then it should be delimited with double quotes. If
a value contains a quote character, then it should be escaped with the
backslash character (the backslash character can escape
itself). Properties that doesn't have values (or basically has a
property of a unit type, so called boolean properties) are represented
with their names only, e.g., ``saluki-sat``. A property can have
multiple values, separated by a comma. Properties wihtout values, can
be also separated with the comma. In fact you can always trade off
space for comma, if you like, e.g., ``saluki-sat,saluki-unsat`` is
equivalent to ``saluki-sat saluki-unsat``:

>>> assert(parse('BAP: saluki-sat,saluki-unsat') == \
parse('BAP: saluki-sat saluki-unsat'))


Comments are parsed into a dictionary, that maps properties into their
values. A property that doesn't have a value is mapped to an empty
list.

>>> parse('BAP: saluki-sat,saluki-unsat beagle-chars=ajdladasn,asd \
           beagle-strings="{hello world}"')
{'saluki-sat': [], 'beagle-chars': ['ajdladasn', 'asd'],
 'saluki-unsat': [], 'beagle-strings': ['{hello world}']}

They can be modifed, and dumped back into a string:

>>> dumps({'saluki-sat': [], 'beagle-chars': ['ajdladasn', 'asd'],
          'saluki-unsat': [], 'beagle-strings': ['{hello world}']})
'BAP: saluki-sat,saluki-unsat beagle-chars=ajdladasn,asd \
 beagle-strings="{hello world}"'


Any special characters inside the property value must be properly
escaped:

>>> parse('BAP: beagle-chars="abc\\'"')
{'beagle-chars': ["abc'"]}

Note: In the examples, we need to escape the backslash, as they are
intended to be run by the doctest system, that will perform one layer
of the expension. So, in the real life, to escape a quote we will
write only one backslash, e.g., "abc\'". Probably, this should be
considered as a bug on the doctest side, as it is assumed, that you
can copy paste an example from the doc to the interpreter and see the
identical results. Here we will get a syntax error from the python
interpreter.

>>> dumps(parse('BAP: beagle-chars="abc\\'"'))
'BAP: beagle-chars="abc\\'"'

Syntactically incorrect code will raise the ``SyntaxError`` exception,
e.g.,

>>> parse('BAP: beagle-words=hello=world')
Traceback (most recent call last):
    ...
SyntaxError: in state key expected <string> got =

## Grammar

comm  ::= "BAP:" <props>
props ::= <prop>
        | <prop> <sep> <props>
prop  ::= <key>
        | <key>=<values>
values ::= <value> | <value> "," <values>
value ::= <word>
key   ::= <word>


Where ``<word>`` is any sequence of word-characters (see WORDCHARS)
constant (letters, numbers and the following two characters: "-" and
":"), e.g., `my-property-name`, or `analysis:property`.


Note: the parser usually accepts more languages that are formally recognized
by the grammar.

"""

import string
from shlex import shlex

WORDCHARS = ''.join(['-:', string.ascii_letters, string.digits])


def parse(comment, debug=0):
    """ Parse comment string.

    Returns a dictionary that maps properties to their values.
    Raises SyntaxError if the comment is syntactically incorrect.
    Returns None if comment doesn't start with the `BAP:` prefix.
    """
    lexer = shlex(comment, posix=True)
    lexer.wordchars = WORDCHARS
    lexer.debug = debug
    lexer.quotes = '"'
    result = {}
    key = ''
    values = []
    state = 'init'

    def error(exp, token):
        "raise a nice error message"
        raise SyntaxError('in state {0} expected {1} got {2}'.
                          format(state, exp, token))

    def push(result, key, values):
        "push binding into the stack"
        if key != '':
            result[key] = values

    for token in lexer:
        if state == 'init':
            if token != 'BAP:':
                return None
            state = 'key'
        elif state == 'key':
            if token == '=':
                error('<string>', token)
            elif token == ',':
                state = 'value'
            else:
                push(result, key, values)
                values = []
                key = token
                state = 'eq'
        elif state == 'eq':
            if token == '=':
                state = 'value'
            else:
                push(result, key, values)
                key = ''
                values = []
                if token == ',':
                    state = 'key'
                else:
                    key = token
                    state = 'eq'
        elif state == 'value':
            values.append(unquote(token))
            state = 'key'

    push(result, key, values)
    return result


def is_valid(comm):
    try:
        return comm.startswith('BAP:') and parse(comm)
    except SyntaxError:
            return False


def dumps(comm):
    """Dump dictionary into a comment string.

    The representation is parseable with the parse function.
    """
    keys = []
    elts = []
    for (key, values) in comm.items():
        if values:
            elts.append('{0}={1}'.format(key, ','.join(
                quote(x) for x in values)))
        else:
            keys.append(key)
    keys.sort()
    elts.sort()
    return ' '.join(x for x in
                    ('BAP:', ','.join(keys), ' '.join(elts)) if x)


def quote(token):
    """delimit a token with quotes if needed.

    The function guarantees that the string representation of the
    token will be parsed into the same token. In case if a token
    contains characters that are no in the set of WORDCHARS symbols,
    that will lead to the splittage of the token during the lexing,
    a pair of double quotes are added to prevent this.

    >>> quote('hello, world')
    '"hello, world"'
    """
    if not token.startswith('"') and set(token) - set(WORDCHARS):
        return '"{}"'.format(''.join('\\'+c if c == '"' else c
                                     for c in token))
    else:
        return token


def unquote(word, quotes='\'"'):
    """removes quotes from both sides of the word.

    The quotes should occur on both sides of the word:

    >>> unquote('"hello"')
    'hello'

    If a quote occurs only on one side of the word, then
    the word is left intact:

    >>> unquote('"hello')
    '"hello'

    The quotes that delimites the world should be equal, i.e.,
    if the word is delimited with double quotes on the left and
    a quote on the right, then it is not considered as delimited,
    so it is not dequoted:

    >>> unquote('"hello\\'')
    '"hello\\''

    Finally, only one layer of quotes is removed,

    >>> unquote('""hello""')
    '"hello"'
    """
    if len(word) > 1 and word[0] == word[-1] \
       and word[0] in quotes and word[-1] in quotes:
        return word[1:-1]
    else:
        return word


if __name__ == "__main__":
    import doctest
    doctest.testmod()
