"""Luraph stage 3 - pseudo-source reconstruction.

Walks the stage-2 disassembly symbolically:

  * ``R[15]`` is tracked as the *last global / member chain* the loader
    fetched (GETGLOBAL / GETTABLE), so the next SETTABLE on the CONFIG
    register (R[14]) can be annotated with a readable name.
  * ``LOADVMK`` constants are resolved to ``string.*`` / ``bit32.*`` names.
  * ``LOADK`` values are turned into quoted Lua literals.

The output is the loader's initialisation reconstructed as pseudo-source:
the CONFIG table, every referenced global, every deobf-helper call and a
statement trace that maps straight back to the VM instruction indexes.
"""

import re

# VM constant indices recovered from the interpreter (M[26] table)
VMK = {5: 'countlz', 6: 'bnot', 7: 'band', 8: 'bor', 9: 'char', 10: 'byte',
       11: 'lshift', 12: 'rshift', 13: 'lrotate', 14: 'rrotate', 15: 'countrz',
       16: 'bxor', 17: 'rep', 18: 'sub', 19: 'len', 20: 'arshift', 21: 'format',
       22: 'floor', 23: 'ceil', 24: 'gsub'}

_STRING_VMK = {9, 10, 17, 18, 19, 21, 24}
_BIT_VMK = {5, 6, 7, 8, 11, 12, 13, 14, 15, 16, 20}

# category detection for CONFIG entries
EXEC_DETECT = {'identifyexecutor', 'islclosure', 'iscclosure', 'getexecutorname',
               'checkcaller', 'isrbxactive', 'gethui', 'getscriptbytecode', 'syn',
               'fluxus', 'krnl', 'electron'}
HTTP_KEYS = {'PostAsync', 'GetAsync', 'HttpService', 'HttpGet', 'request',
             'http_request', 'HttpPost'}
ANTI_TAMPER = {'Path2DControlPoint', 'Path2D', 'Path2DWaypoint'}
ROBLOX_API = {'Instance', 'game', 'workspace', 'Enum', 'UDim2', 'UDim', 'Vector2',
              'Vector3', 'CFrame', 'Color3', 'TweenService', 'RunService',
              'UserInputService', 'GuiService', 'Lighting', 'Players',
              'ReplicatedStorage', 'DataModel', 'Folder', 'ScreenGui', 'TextLabel',
              'TextButton', 'Frame', 'UIScale', 'UISizeConstraint', 'UIListLayout',
              'UIPadding', 'TextBox', 'ScrollingFrame', 'UIGradient', 'Corner'}
LUA_STDLIB = {'setmetatable', 'getmetatable', 'rawget', 'rawset', 'pcall', 'xpcall',
              'error', 'assert', 'select', 'type', 'typeof', 'tostring', 'tonumber',
              'unpack', 'table', 'string', 'math', 'bit32', 'coroutine', 'task',
              'debug', 'utf8', 'next', 'pairs', 'ipairs', 'setfenv', 'getfenv',
              'newproxy', 'loadstring', 'load'}
UI_EVENT = {'Disconnect', 'Connected', 'Deny', 'Allow', 'AccessModifierType',
            'EnumType', 'Name', 'ClassName', 'Parent', 'AnchorPoint', 'PaddingLeft',
            'PaddingTop', 'AbsoluteSize', 'MinSize', 'MaxSize', 'LayoutOrder',
            'NextInteger', 'NextNumber', 'IsStudio', 'FromValue', 'Workspace',
            'Create', 'Shuffle', 'Clone', 'IsA', 'GetChildren', 'WaitForChild',
            'FindFirstChild', 'delay', 'wait', 'spawn', 'defer', 'yield', 'wrap',
            'running', 'status', 'close', 'cancel', 'isyieldable', 'create',
            'GetInfo', 'getinfo', 'gmatch', 'find', 'sub', 'byte', 'char', 'rep',
            'pack', 'format', 'concat', 'insert', 'traceback', 'namewhat', 'what',
            'linedefined', 'lastlinedefined', 'short_src', 'currentline',
            'nparams', 'isvararg', 'source', 'C'}

CAT_ORDER = ['EXECUTOR-DETECT', 'HTTP/KEYSYSTEM', 'ANTI-TAMPER', 'ROBLOX-API',
             'UI/EVENT-STRS', 'LUA-STDLIB', 'MISC']


def quote_str(s):
    """Quote a bare value unless it is a known symbol / number."""
    if s in ('nil', 'true', 'false'):
        return s
    if (s.startswith('_G.') or s.startswith('PROTO') or s.startswith('string.')
            or s.startswith('bit32.') or s.startswith('math.')):
        return s
    if re.match(r'^-?\d', s):
        return s
    return repr(s)


def category(name):
    n = name.replace('_G.', '').split('.')[0].strip('"\'')
    if n in EXEC_DETECT:
        return 'EXECUTOR-DETECT'
    if n in HTTP_KEYS:
        return 'HTTP/KEYSYSTEM'
    if n in ANTI_TAMPER:
        return 'ANTI-TAMPER'
    if n in ROBLOX_API:
        return 'ROBLOX-API'
    if n in UI_EVENT:
        return 'UI/EVENT-STRS'
    if n in LUA_STDLIB:
        return 'LUA-STDLIB'
    return 'MISC'


def parse_disasm(text):
    """Parse devirtualized disassembly lines back into instruction dicts."""
    instrs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(';'):
            continue
        m = re.match(r'(\d+):\s+(\w+\??)\s+(.*?)\s*;', line)
        if not m:
            continue
        idx, op = int(m.group(1)), m.group(2)
        fields = dict((fm.group(1), fm.group(2))
                      for fm in re.finditer(r'([A-Za-z]+)=(\S+)', m.group(3)))
        instrs.append({'idx': idx, 'op': op, **fields})
    return instrs


def reconstruct(instrs, strings):
    """Return the pseudo-source text for a proto's instruction list.

    ``instrs`` are the parsed disassembly dicts (see parse_disasm),
    ``strings`` the parsed string table (see luraph_devirt.parse_strings).
    """
    R = {'15': None}
    config = {}
    globals_used = []
    calls = []
    flow = []

    def fmt_val(tok):
        if tok == 'nil':
            return 'nil'
        if tok.startswith('table'):
            return 'PROTO'
        return quote_str(tok)

    for ins in instrs:
        op = ins['op']
        idx = ins['idx']
        F, g, b, D, L, K = (ins.get(k, 'nil') for k in ('F', 'g', 'b', 'D', 'L', 'K'))

        if op == 'GETGLOBAL':
            name = strings.get(int(D), D) if D.isdigit() else D
            R['15'] = '_G.%s' % name
            if name not in globals_used:
                globals_used.append(name)
            flow.append((idx, 'TMP = _G.%s' % name))

        elif op == 'GETTABLE':
            base = R.get('15', 'TMP')
            if b != 'nil':
                member = strings.get(int(b), b) if b.isdigit() else b
                R['15'] = '%s.%s' % (base, member)
                flow.append((idx, 'TMP = %s.%s' % (base, member)))
            else:
                R['15'] = '%s[R%s]' % (base, F)
                flow.append((idx, 'TMP = %s[R%s]' % (base, F)))

        elif op == 'SETTABLE':
            if F == '14':
                key = D
                val = fmt_val(g) if g != 'nil' else (R.get(K, 'R%s' % K) or 'nil')
                config[key] = (idx, val)
                flow.append((idx, 'CONFIG[%s] = %s' % (key, val)))
            else:
                flow.append((idx, 'R%s[...] = ... (internal)' % F))

        elif op == 'LOADVMK':
            n = int(L)
            if n in _STRING_VMK:
                R[K] = 'string.%s' % VMK[n]
            elif n in _BIT_VMK:
                R[K] = 'bit32.%s' % VMK[n]
            else:
                R[K] = 'VMK[%s]' % L
            flow.append((idx, 'R%s = %s' % (K, R[K])))

        elif op == 'LOADK':
            val = fmt_val(g)
            R[L] = val
            flow.append((idx, 'R%s = %s' % (L, val)))

        elif op == 'LOADNIL':
            flow.append((idx, 'R%s..R%s = nil' % (F, K)))

        elif op == 'CALL1':
            fn = R.get(K, 'R%s' % K)
            calls.append((idx, fn))
            flow.append((idx, '%s(...)  -- deobf call' % fn))

        elif op == 'CALL':
            fn = R.get(L, 'R%s' % L) if L != '0' else R.get(K, 'R%s' % K)
            calls.append((idx, fn))
            flow.append((idx, '%s(...)  -- deobf call' % fn))

        elif op in ('MOVE', 'MOVE?'):
            src = R.get(L, 'R%s' % L) if L != '0' else F
            dst = K if K != '0' else F
            R[dst] = src
            flow.append((idx, 'R%s = %s' % (dst, src)))

        elif op in ('SUB', 'ADD', 'UNM?', 'LEN', 'EQ', 'LT', 'LE', 'EQ?', 'TEST',
                    'VARARG', 'VARARG2', 'GETUPVAL', 'GETTABLE2', 'SETGLOBAL?',
                    'CONCAT?', 'DIV?', 'LOADK2', 'GETTABLE', 'SETTABLE'):
            flow.append((idx, '%s (internal)' % op))
        else:
            flow.append((idx, '%s (?)' % op))

    by_cat = {}
    for key, (idx, val) in config.items():
        name = val.replace('_G.', '').split('.')[0].strip('"\'')
        by_cat.setdefault(category(name), []).append((key, idx, val))

    out = []
    out.append('-- ============================================================')
    out.append('-- Stage 3: pseudo-source reconstruction')
    out.append('-- proto 39 (main chunk) - Luraph v14.7 devirtualized')
    out.append('-- %d instructions | %d CONFIG entries | %d globals | %d calls'
               % (len(instrs), len(config), len(globals_used), len(calls)))
    out.append('-- ============================================================')
    out.append('')
    out.append('-- [[ CONFIG TABLE (R[14]) ]] -- integer-key env/const table')
    out.append('local CONFIG = {')
    for c in CAT_ORDER:
        entries = by_cat.get(c, [])
        if not entries:
            continue
        out.append('')
        out.append('    -- %s (%d)' % (c, len(entries)))
        for key, idx, val in sorted(entries, key=lambda x: int(x[0]) if str(x[0]).isdigit() else 0):
            out.append('    [%s] = %s,  -- @%d' % (key, val, idx))
    out.append('}')
    out.append('')
    out.append('-- [[ Globals referenced ]]')
    for n in globals_used:
        out.append('-- _G.%s' % n)
    out.append('')
    out.append('-- [[ Deobf helper calls ]]')
    seen = []
    for idx, fn in calls:
        if fn not in seen:
            seen.append(fn)
            out.append('-- @%d: %s(...)' % (idx, fn))
    out.append('')
    out.append('-- [[ Statement trace ]]')
    for idx, s in flow:
        out.append('%5d: %s' % (idx, s))

    return '\n'.join(out)
