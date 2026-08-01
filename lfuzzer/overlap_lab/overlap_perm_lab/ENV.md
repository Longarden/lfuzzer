# overlap_perm_lab — 실행 환경 기록 (iter21~ 시작 시점, 2026-05-13)

| 항목 | 값 |
|---|---|
| OS | Linux BOOK-MF2J51IVI9 6.6.87.2-microsoft-standard-WSL2 |
| gcc | 13.3.0-6ubuntu2~24.04.1 |
| binutils (ld) | 2.42-4ubuntu2.8 |
| glibc | 2.39-0ubuntu8.7 |
| python3 | 3.12.3 |
| pyelftools | 0.32 |
| ASLR (kernel.randomize_va_space) | 2 (full) — 단, 본 lab 타깃은 -no-pie 라 executable 영역에는 영향 없음 |
| 빌드 옵션 (공통) | -O0 -g -fno-pic -no-pie + RELRO 변형(-z norelro / -z relro / -z relro -z now) |

재현 명령 (각 iterNN 동일):
```
cd /home/garden/PE/Lfuzzer/overlap_perm_lab
python3 iterNN.py
./detect_overlap.py iter_outputs/iterNN/I*
```
