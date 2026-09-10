#!/usr/bin/env python3
"""SCV 4.5.3 string-table deobfuscator — STATIC analysis only, never executes PHP.
Reverses the charset-substitution cipher used by rtorxlw5pr()/lq58kjeoslnkk6()."""
import sys, re, json

PHP = sys.argv[1] if len(sys.argv) > 1 else 'bold-booster-lab.php'
src = open(PHP, encoding='utf-8', errors='replace').read()

def php_unescape(s):
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == '\\' and i + 1 < len(s) and s[i+1] in ('\\', "'"):
            out.append(s[i+1]); i += 2; continue
        out.append(c); i += 1
    return ''.join(out)

# ---- 1. extract the string table (array_merge body of lq58kjeoslnkk6) ----
anchor = src.find('$a=array_merge(')
if anchor < 0:
    sys.exit('FATAL: string table not found')
i = anchor + len('$a=array_merge(')
depth, in_str = 1, False
while i < len(src) and depth > 0:
    c = src[i]
    if in_str:
        if c == '\\': i += 2; continue
        if c == "'": in_str = False
    else:
        if c == "'": in_str = True
        elif c == '(': depth += 1
        elif c == ')': depth -= 1
    i += 1
body = src[anchor + len('$a=array_merge('): i - 1]

strings, j = [], 0
while j < len(body):
    if body[j] == "'":
        k, buf = j + 1, []
        while k < len(body):
            if body[k] == '\\' and k+1 < len(body) and body[k+1] in ('\\', "'"):
                buf.append(body[k:k+2]); k += 2; continue
            if body[k] == "'": break
            buf.append(body[k]); k += 1
        strings.append(php_unescape(''.join(buf)))
        j = k + 1
    else:
        j += 1

# ---- 2. extract $f (target) and $t (source) charsets from rtorxlw5pr ----
# decoder fn name is randomized per sample: function NAME($i){$e=TABLEFN($i);$f=...
mf = re.search(r"function (\w+)\(\$i\)\{\\\$e=\w+\(\\\$i\);(.*?)return \\\$r;", src, re.S) \
     or re.search(r"function (\w+)\(\$i\)\{\$e=\w+\(\$i\);(.*?)return \$r;", src, re.S)
if not mf:
    sys.exit('FATAL: decoder fn not found')
fb = mf.group(2)
f_part, _, t_part = fb.partition("$t=")
f_part = f_part.partition("$f=")[2]

QUOTED = re.compile(r"'((?:\\.|[^'\\])*)'", re.S)
f = ''.join(php_unescape(s) for s in QUOTED.findall(f_part))
t = ''.join(php_unescape(s) for s in QUOTED.findall(t_part))

if len(f) != len(t):
    print(f'WARN: charset length mismatch f={len(f)} t={len(t)}', file=sys.stderr)

tmap = {c: (f[p] if p < len(f) else c) for p, c in enumerate(t)}

decoded = [''.join(tmap.get(ch, ch) for ch in s) for s in strings]

# ---- 3. report ----
print(f'# table entries: {len(strings)}  |  f charset {len(f)} chars, t charset {len(t)} chars')
print(f'# unique decoded: {len(set(decoded))}')
print('=' * 60)
for idx, d in enumerate(decoded):
    print(f'[{idx:4d}] {d}')
