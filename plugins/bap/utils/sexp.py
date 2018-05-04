from shlex import shlex


class Parser(object):
    def __init__(self, instream=None, infile=None):
        self.lexer = shlex(instream, infile)
        self.lexer.wordchars += ":-/@#$%^&*+`\\'"
        self.lexer.commenters = ";"

    def __iter__(self):
        return self

    def __next__(self):
        return self.next()

    def next(self):
        token = self.lexer.get_token()
        if token == self.lexer.eof:
            raise StopIteration
        elif token == '(':
            return self._parse_list()
        else:
            return token

    def _parse_list(self):
        elts = []
        for token in self.lexer:
            if token == ')':
                break
            elif token == '(':
                elts.append(self._parse_list())
            else:
                elts.append(token)
        return elts


def loads(ins):
    parser = Parser(ins)
    return [x for x in parser]


def parse(ins):
    parser = Parser(ins)
    return parser.next()
