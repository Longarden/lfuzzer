#!/usr/bin/env python3
"""
analyze.py — gdb_kernel.log / gdb_main.log 에서 텍스트(0x401xxx) 페이지의
실제 권한을 추출해 표로 출력. 가설 판정(후자 우선 / 최소 권한 / 기타)을 위한 근거 자료.
"""

import os, re, sys

ROOT = 'results'

PERM_RE = re.compile(r'^\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+([rwxp-]+)')


def parse_maps(path):
    out = []
    if not os.path.exists(path): return out
    with open(path) as f:
        for line in f:
            m = PERM_RE.match(line)
            if not m: continue
            start = int(m.group(1), 16); end = int(m.group(2), 16); perm = m.group(3)
            out.append((start, end, perm))
    return out


def perm_at(maps, addr):
    for s, e, p in maps:
        if s <= addr < e:
            return p
    return '-----'


def exit_status(path):
    if not os.path.exists(path): return '?'
    with open(path) as f:
        first = f.readline().strip()
    m = re.match(r'#\s*exit=(-?\d+)', first)
    if m:
        rc = int(m.group(1))
        if rc == -11: return 'SEGV'
        if rc == 0:   return 'ok'
        return f'rc={rc}'
    return first


def main():
    targets = sorted(os.listdir(ROOT))
    print(f'{"target":<20} {"variant":<28} {"plain":<6} {"kern@0x401":<10} {"main@0x401":<10}')
    print('-' * 80)
    for t in targets:
        tdir = os.path.join(ROOT, t)
        variants = sorted(set(f.split('.')[0] for f in os.listdir(tdir)))
        for v in variants:
            plain = exit_status(os.path.join(tdir, f'{v}.plain.log'))
            km = parse_maps(os.path.join(tdir, f'{v}.gdb_kernel.log'))
            mm = parse_maps(os.path.join(tdir, f'{v}.gdb_main.log'))
            pk = perm_at(km, 0x401000)
            pm = perm_at(mm, 0x401000)
            print(f'{t:<20} {v:<28} {plain:<6} {pk:<10} {pm:<10}')


if __name__ == '__main__':
    main()
