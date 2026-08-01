"""
harness.py — 0508 액션 A 자가 피드백 루프용 코어.

each iteration:
  spec_list -> make variants -> plain + gdb_kernel + gdb_main 실행 ->
  /proc maps 파싱 -> 관찰 결과 record -> STATE.json + ITER_LOG.md 업데이트.

iterNN_*.py 는 spec_list 와 hypothesis 만 정의하고 harness 의 run_iteration 을 호출.
"""

import os, struct, subprocess, re, json, time
from pathlib import Path

ROOT       = Path('/home/garden/PE/Lfuzzer/overlap_perm_lab')
STATE_PATH = ROOT / 'STATE.json'
LOG_PATH   = ROOT / 'ITER_LOG.md'
OUT_ROOT   = ROOT / 'iter_outputs'

PHDR_SIZE = 56
PHDR_FIELDS = {
    'type':   (0, 4),
    'flags':  (4, 4),
    'offset': (8, 8),
    'vaddr':  (16, 8),
    'paddr':  (24, 8),
    'filesz': (32, 8),
    'memsz':  (40, 8),
    'align':  (48, 8),
}

PT_LOAD      = 1
PT_DYNAMIC   = 2
PT_GNU_RELRO = 0x6474e552

PERM_RE = re.compile(r'^\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+([rwxp-]+)')


def load_phdr_table(data):
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]
    return e_phoff, e_phnum


def apply_patches(data, patches):
    """patches = list of dicts:
       - field patch:  {'phdr_idx': N, 'field': 'vaddr', 'value': 0x...}
       - swap:         {'swap': (i, j)}
    """
    e_phoff, e_phnum = load_phdr_table(data)
    out = bytearray(data)
    for p in patches:
        if 'swap' in p:
            i, j = p['swap']
            a = e_phoff + i * PHDR_SIZE
            b = e_phoff + j * PHDR_SIZE
            A = bytes(out[a:a+PHDR_SIZE]); B = bytes(out[b:b+PHDR_SIZE])
            out[a:a+PHDR_SIZE] = B
            out[b:b+PHDR_SIZE] = A
        else:
            idx = p['phdr_idx']
            off, sz = PHDR_FIELDS[p['field']]
            abs_off = e_phoff + idx * PHDR_SIZE + off
            fmt = '<Q' if sz == 8 else '<I'
            struct.pack_into(fmt, out, abs_off, p['value'])
    return bytes(out)


def make_variant(base_path, patches, out_path):
    data = Path(base_path).read_bytes()
    patched = apply_patches(data, patches)
    Path(out_path).write_bytes(patched)
    os.chmod(out_path, 0o755)


def _write(p, body):
    Path(p).write_text(body)


def run_plain(path, out_path):
    try:
        r = subprocess.run([str(path)], timeout=3, capture_output=True)
        body = (f'# exit={r.returncode}\n'
                f'# --- stdout ---\n{r.stdout.decode(errors="replace")}\n'
                f'# --- stderr ---\n{r.stderr.decode(errors="replace")}\n')
    except subprocess.TimeoutExpired:
        body = '# TIMEOUT\n'
    except Exception as e:
        body = f'# ERROR: {e}\n'
    _write(out_path, body)


def run_gdb(path, out_path, mode):
    """mode='kernel' → starti (kernel snapshot)
       mode='main'   → break main + run (post RELRO snapshot)"""
    if mode == 'kernel':
        cmd = ['gdb', '-batch', '-nx',
               '-ex', 'set debuginfod enabled off',
               '-ex', 'starti',
               '-ex', 'info proc mappings',
               '-ex', 'quit', str(path)]
    else:
        cmd = ['gdb', '-batch', '-nx',
               '-ex', 'set debuginfod enabled off',
               '-ex', 'set breakpoint pending on',
               '-ex', 'break main',
               '-ex', 'run',
               '-ex', 'info proc mappings',
               '-ex', 'quit', str(path)]
    try:
        r = subprocess.run(cmd, timeout=10, capture_output=True)
        body = (f'# exit={r.returncode}\n'
                f'# --- stdout ---\n{r.stdout.decode(errors="replace")}\n'
                f'# --- stderr ---\n{r.stderr.decode(errors="replace")[:6000]}\n')
    except subprocess.TimeoutExpired:
        body = '# TIMEOUT\n'
    except Exception as e:
        body = f'# ERROR: {e}\n'
    _write(out_path, body)


def parse_maps(log_path):
    out = []
    p = Path(log_path)
    if not p.exists():
        return out
    for line in p.read_text().splitlines():
        m = PERM_RE.match(line)
        if m:
            s = int(m.group(1), 16); e = int(m.group(2), 16); perm = m.group(3)
            out.append((s, e, perm))
    return out


def perm_at(maps, addr):
    for s, e, p in maps:
        if s <= addr < e:
            return p
    return '(unmapped)'


def exit_code(plain_path):
    p = Path(plain_path)
    if not p.exists(): return None
    first = (p.read_text().splitlines() or [''])[0]
    m = re.match(r'#\s*exit=(-?\d+)', first)
    return int(m.group(1)) if m else None


def run_iteration(N, title, spec_list, base='target_partial', observe_addrs=None):
    iter_dir = OUT_ROOT / f'iter{N:02d}'
    iter_dir.mkdir(parents=True, exist_ok=True)
    addrs_default = observe_addrs or [0x401000, 0x402000, 0x403000]

    obs = []
    for spec in spec_list:
        name = spec['name']
        b = spec.get('base', base)
        base_path = ROOT / b
        var_path = iter_dir / name
        make_variant(base_path, spec['patches'], var_path)

        plain_log = iter_dir / f'{name}.plain.log'
        gdb_k     = iter_dir / f'{name}.gdb_kernel.log'
        gdb_m     = iter_dir / f'{name}.gdb_main.log'

        run_plain(var_path, plain_log)
        run_gdb(var_path, gdb_k, 'kernel')
        run_gdb(var_path, gdb_m, 'main')

        k_maps = parse_maps(gdb_k)
        m_maps = parse_maps(gdb_m)
        addrs  = spec.get('observe_addrs') or addrs_default

        record = {
            'name': name,
            'note': spec.get('note', ''),
            'plain_exit': exit_code(plain_log),
            'kernel_perm': {f'{a:#x}': perm_at(k_maps, a) for a in addrs},
            'main_perm':   {f'{a:#x}': perm_at(m_maps, a) for a in addrs},
        }
        obs.append(record)
    return obs


def load_state():
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text())
    return {
        'iteration': 0,
        'open_questions': [],
        'findings': [],
        'backlog': [],
        'completed_iterations': [],
    }


def save_state(state):
    STATE_PATH.write_text(json.dumps(state, indent=2, ensure_ascii=False))


def log(text):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open('a') as f:
        f.write(text.rstrip() + '\n')


def commit_iteration(N, title, hypothesis, obs, verdict, new_backlog=None, new_findings=None):
    """state 와 ITER_LOG.md 에 일관되게 반영."""
    state = load_state()
    state['iteration'] = N
    state['completed_iterations'].append({
        'iter': N,
        'title': title,
        'hypothesis': hypothesis,
        'verdict': verdict,
        'obs': obs,
        'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
    })
    if new_findings:
        state['findings'].extend(new_findings)
    if new_backlog:
        state['backlog'].extend(new_backlog)
    save_state(state)

    md = [f'\n## iter{N:02d} — {title}',
          f'- 가설: {hypothesis}',
          f'- 판정: {verdict}',
          '- 관찰:']
    for r in obs:
        md.append(f'  - {r["name"]} | plain={r["plain_exit"]} | '
                  f'kernel={r["kernel_perm"]} | main={r["main_perm"]}'
                  + (f' | {r["note"]}' if r.get('note') else ''))
    if new_findings:
        md.append('- 새 finding:')
        for f in new_findings:
            md.append(f'  - {f}')
    if new_backlog:
        md.append('- 새 backlog:')
        for b in new_backlog:
            md.append(f'  - {b}')
    log('\n'.join(md))
