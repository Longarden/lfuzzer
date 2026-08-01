"""
전체 crash ELF를 GDB로 자동 분석해서 크래시 지점별로 분류
"""
import os, subprocess
from collections import defaultdict

CRASH_DIR = "crashes_shuffle"
RESULT    = "crash_analysis_result.txt"

crash_files = sorted(f for f in os.listdir(CRASH_DIR) if f.endswith(".elf"))
print(f"총 {len(crash_files)}개 분석 시작...\n")

groups = defaultdict(list)  # 크래시 지점 → 파일 목록

for i, fname in enumerate(crash_files):
    path = os.path.join(CRASH_DIR, fname)
    os.chmod(path, 0o755)

    result = subprocess.run(
        ["gdb", "-batch",
         "-ex", "run",
         "-ex", "bt 3",          # 상위 3 프레임만
         path],
        capture_output=True, text=True, timeout=10
    )
    output = result.stderr + result.stdout

    # 크래시 함수 추출 (#0 라인)
    crash_func = "UNKNOWN"
    for line in output.splitlines():
        if line.strip().startswith("#0"):
            crash_func = line.strip()
            break

    groups[crash_func].append(fname)

    if (i + 1) % 200 == 0:
        print(f"  [{i+1}/{len(crash_files)}] 진행 중...")

# 결과 출력
print("\n===== 크래시 지점별 분류 =====\n")
with open(RESULT, "w") as out:
    for func, files in sorted(groups.items(), key=lambda x: -len(x[1])):
        header = f"[{len(files)}개] {func}"
        print(header)
        out.write(header + "\n")
        for f in files[:3]:
            print(f"  {f}")
            out.write(f"  {f}\n")
        if len(files) > 3:
            print(f"  ... 외 {len(files)-3}개")
            out.write(f"  ... 외 {len(files)-3}개\n")
        out.write("\n")

print(f"\n유니크 크래시 경로: {len(groups)}개")
print(f"결과 저장: {RESULT}")
