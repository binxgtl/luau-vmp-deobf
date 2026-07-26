"""Minimal Lua/Luau tokenizer, good enough for machine-generated loader sources."""
import re

KEYWORDS = {
    'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for', 'function', 'if',
    'in', 'local', 'nil', 'not', 'or', 'repeat', 'return', 'then', 'true', 'until',
    'while', 'continue',
}

TOK_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<lcomment>--\[(?P<lceq>=*)\[)
  | (?P<comment>--[^\n]*)
  | (?P<lstr>\[(?P<lseq>=*)\[)
  | (?P<num>0[xX][0-9a-fA-F]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)
  | (?P<name>[A-Za-z_][A-Za-z_0-9]*)
  | (?P<str>'|")
  | (?P<op>\.\.\.|\.\.=|\.\.|==|~=|<=|>=|::|\+=|-=|\*=|/=|%=|\^=|//|[-+*/%^#<>=(){}\[\];:,.])
""", re.X)


class Tok:
    __slots__ = ('kind', 'val', 'pos')

    def __init__(self, kind, val, pos):
        self.kind, self.val, self.pos = kind, val, pos

    def __repr__(self):
        return '%s(%r)' % (self.kind, self.val)


def tokenize(src):
    toks, i, n = [], 0, len(src)
    while i < n:
        m = TOK_RE.match(src, i)
        if not m:
            raise SyntaxError('lex error at %d: %r' % (i, src[i:i + 40]))
        if m.group('ws') is not None or m.group('comment') is not None:
            i = m.end()
            continue
        if m.group('lcomment') is not None:
            close = ']' + m.group('lceq') + ']'
            j = src.find(close, m.end())
            i = n if j < 0 else j + len(close)
            continue
        if m.group('lstr') is not None:
            close = ']' + m.group('lseq') + ']'
            j = src.find(close, m.end())
            j = n if j < 0 else j + len(close)
            toks.append(Tok('str', src[i:j], i))
            i = j
            continue
        if m.group('str') is not None:
            q, j = m.group('str'), i + 1
            while j < n:
                if src[j] == '\\':
                    j += 2
                    continue
                if src[j] == q:
                    j += 1
                    break
                j += 1
            toks.append(Tok('str', src[i:j], i))
            i = j
            continue
        if m.group('num') is not None:
            toks.append(Tok('num', m.group('num'), i))
        elif m.group('name') is not None:
            v = m.group('name')
            toks.append(Tok('kw' if v in KEYWORDS else 'name', v, i))
        else:
            toks.append(Tok('op', m.group('op'), i))
        i = m.end()
    return toks


def render(toks):
    out, prev = [], None
    for t in toks:
        if prev is not None and prev.kind in ('name', 'kw', 'num') and t.kind in ('name', 'kw', 'num'):
            out.append(' ')
        out.append(t.val)
        prev = t
    return ''.join(out)


def split_strings(src):
    """Split source into [('code'|'str', text), ...] so transforms skip literals."""
    out, i, n, buf = [], 0, len(src), []
    while i < n:
        c = src[i]
        if c in "'\"":
            out.append(('code', ''.join(buf)))
            buf = []
            q, j = c, i + 1
            while j < n:
                if src[j] == '\\':
                    j += 2
                    continue
                if src[j] == q:
                    j += 1
                    break
                j += 1
            out.append(('str', src[i:j]))
            i = j
            continue
        if c == '[' and i + 1 < n and src[i + 1] in '[=':
            m = re.match(r"\[(=*)\[", src[i:])
            if m:
                close = ']' + m.group(1) + ']'
                j = src.find(close, i + len(m.group(0)))
                j = n if j < 0 else j + len(close)
                out.append(('code', ''.join(buf)))
                buf = []
                out.append(('str', src[i:j]))
                i = j
                continue
        if src.startswith('--', i):
            m = re.match(r"--\[(=*)\[", src[i:])
            if m:
                close = ']' + m.group(1) + ']'
                j = src.find(close, i + len(m.group(0)))
                j = n if j < 0 else j + len(close)
            else:
                j = src.find('\n', i)
                j = n if j < 0 else j
            out.append(('code', ''.join(buf)))
            buf = []
            out.append(('str', src[i:j]))
            i = j
            continue
        buf.append(c)
        i += 1
    out.append(('code', ''.join(buf)))
    return out


ESC = {'a': 7, 'b': 8, 'f': 12, 'n': 10, 'r': 13, 't': 9, 'v': 11,
       '\\': 92, '"': 34, "'": 39, '\n': 10}


def lua_unescape(body):
    """Decode the *contents* of a Lua short string literal into bytes."""
    out, i = bytearray(), 0
    while i < len(body):
        c = body[i]
        if c != '\\':
            out.append(ord(c) & 0xFF)
            i += 1
            continue
        i += 1
        if i >= len(body):
            break
        d = body[i]
        if d.isdigit():
            num = ''
            while i < len(body) and body[i].isdigit() and len(num) < 3:
                num += body[i]
                i += 1
            out.append(int(num) & 0xFF)
            continue
        out.append(ESC.get(d, ord(d)) & 0xFF)
        i += 1
    return bytes(out)


def lua_escape(b):
    out = []
    for ch in b:
        if ch == 34:
            out.append('\\"')
        elif ch == 92:
            out.append('\\\\')
        elif 32 <= ch < 127:
            out.append(chr(ch))
        elif ch == 10:
            out.append('\\n')
        elif ch == 9:
            out.append('\\t')
        else:
            out.append('\\%d' % ch)
    return '"' + ''.join(out) + '"'
