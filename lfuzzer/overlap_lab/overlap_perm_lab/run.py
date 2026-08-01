#!/usr/bin/env python3
"""
run.py — 변형 ELF 들을 두 가지 방식으로 실행하고 권한 관찰 자료를 모은다.

1) plain run: 그냥 실행. exit code / stderr / stdout(/proc/self/maps 덤프) 수집.
2) strace run: mmap, mprotect, openat, execve 추적 → ld.so 가 동일 가상주소에
   어떤 PROT_* 로 매핑/재매핑을 적용했는지 확인.

결과는 results/<target>/<variant>.{plain,strace,maps}.log 로 저장.
"""

import os, sys, subprocess, shlex

VARIANTS_ROOT = 'variants'
RESULTS_ROOT  = 'results'

def run_plain(path, out):
    try:
        r = subprocess.run([path], timeout=3,
                           capture_output=True)
        body = (
            f'# exit={r.returncode}\n'
            f'# --- stdout ---\n{r.stdout.decode(errors="replace")}\n'
            f'# --- stderr ---\n{r.stderr.decode(errors="replace")}\n'
        )
    except subprocess.TimeoutExpired:
        body = '# TIMEOUT\n'
    except Exception as e:
        body = f'# ERROR: {e}\n'
    with open(out, 'w') as f:
        f.write(body)


def run_gdb_kernel_maps(path, out):
    """gdb starti 로 entry point에서 정지 → 커널이 PT_LOAD를 어떻게 매핑했는지 캡처.
    ld.so 가 mmap/mprotect 호출하기 전 상태."""
    cmd = ['gdb', '-batch', '-nx',
           '-ex', 'set debuginfod enabled off',
           '-ex', 'starti',
           '-ex', 'info proc mappings',
           '-ex', 'quit', path]
    try:
        r = subprocess.run(cmd, timeout=10, capture_output=True)
        body = (
            f'# exit={r.returncode}\n'
            f'# --- gdb stdout ---\n{r.stdout.decode(errors="replace")}\n'
            f'# --- gdb stderr ---\n{r.stderr.decode(errors="replace")[:4000]}\n'
        )
    except subprocess.TimeoutExpired:
        body = '# TIMEOUT\n'
    except Exception as e:
        body = f'# ERROR: {e}\n'
    with open(out, 'w') as f:
        f.write(body)


def run_gdb_main_maps(path, out):
    """가능하면 main 에 도달한 시점의 maps 캡처 (RELRO 적용 후).
    main 도달 실패 시 마지막까지의 상태가 stderr에 남는다."""
    cmd = ['gdb', '-batch', '-nx',
           '-ex', 'set debuginfod enabled off',
           '-ex', 'set breakpoint pending on',
           '-ex', 'break main',
           '-ex', 'run',
           '-ex', 'info proc mappings',
           '-ex', 'quit', path]
    try:
        r = subprocess.run(cmd, timeout=10, capture_output=True)
        body = (
            f'# exit={r.returncode}\n'
            f'# --- gdb stdout ---\n{r.stdout.decode(errors="replace")}\n'
            f'# --- gdb stderr ---\n{r.stderr.decode(errors="replace")[:4000]}\n'
        )
    except subprocess.TimeoutExpired:
        body = '# TIMEOUT\n'
    except Exception as e:
        body = f'# ERROR: {e}\n'
    with open(out, 'w') as f:
        f.write(body)


def run_strace(path, out):
    cmd = ['strace', '-f', '-e', 'trace=execve,mmap,mprotect,openat,exit_group,rt_sigaction', path]
    try:
        r = subprocess.run(cmd, timeout=5, capture_output=True)
        body = (
            f'# exit={r.returncode}\n'
            f'# --- strace stderr (truncated to 12KB) ---\n'
            f'{r.stderr.decode(errors="replace")[:12000]}\n'
        )
    except subprocess.TimeoutExpired:
        body = '# TIMEOUT\n'
    except Exception as e:
        body = f'# ERROR: {e}\n'
    with open(out, 'w') as f:
        f.write(body)


def main():
    if not os.path.isdir(VARIANTS_ROOT):
        print('variants/ 없음. mutate.py 먼저 실행.')
        sys.exit(1)

    for target in sorted(os.listdir(VARIANTS_ROOT)):
        tdir = os.path.join(VARIANTS_ROOT, target)
        if not os.path.isdir(tdir): continue
        odir = os.path.join(RESULTS_ROOT, target)
        os.makedirs(odir, exist_ok=True)
        for v in sorted(os.listdir(tdir)):
            vpath = os.path.join(tdir, v)
            print(f'[{target}] {v}')
            run_plain (vpath, os.path.join(odir, f'{v}.plain.log'))
            run_strace(vpath, os.path.join(odir, f'{v}.strace.log'))
            run_gdb_kernel_maps(vpath, os.path.join(odir, f'{v}.gdb_kernel.log'))
            run_gdb_main_maps  (vpath, os.path.join(odir, f'{v}.gdb_main.log'))


if __name__ == '__main__':
    main()
