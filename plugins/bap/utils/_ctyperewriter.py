import re

_REWRITERS = (
    (r'(struct|enum|union) ([^{} ]*);', r'\1 \2; typedef \1 \2 \2;'),
    (r'unsigned __int(8|16|32|64)', r'uint\1_t'),
    (r'(signed )?__int(8|16|32|64)', r'int\2_t'),
    (r'__(cdecl|noreturn)', r'__attribute__((\1))'),
    ('r^%', r'__'),
    (r'_QWORD', r'int64_t'),
    (r'_DWORD', r'int32_t'),
    (r'_WORD', r'int16_t'),
    (r'_BYTE', r'int8_t'),
)


class Rewriter(object):
    def __init__(self):
        self.rewriters = []
        for (patt, subst) in _REWRITERS:
            self.rewriters.append((re.compile(patt), subst))

    def translate(self, expr):
        for (regex, subst) in self.rewriters:
            expr = regex.subs(subst, expr)
        return expr
