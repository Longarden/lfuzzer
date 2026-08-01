# lfuzzer.py — 공통 실행+로깅 모듈
import os, subprocess

# ELF 바이너리를 실행하고 결과를 기록하는 함수
def run_elf(elf_bytes, label, log_path, crash_dir="crashes_lfuzzer"):

    tmp = "./mutated_tmp"  # 임시 실행 파일 경로

    # 1. 변형된 ELF를 파일로 저장
    with open(tmp, "wb") as f:
        f.write(elf_bytes)

    # 실행 권한 부여 (chmod +x)
    os.chmod(tmp, 0o755)

    try:
        # 2. ELF 실행
        r = subprocess.run(
            [tmp],
            timeout=3,  # 3초 이상 실행되면 강제 종료
            stdout=subprocess.DEVNULL,   # 표준 출력 버림
            stderr=subprocess.PIPE       # 에러 출력만 캡처
        )

        # 기본 상태: 종료 코드
        status = f"exit={r.returncode}"

        # 비정상 종료일 경우 stderr 일부를 추가
        if r.returncode != 0:
            msg = r.stderr[:120].decode(errors='replace').strip()
            if msg:
                status += f" | {msg}"

    # 실행이 너무 오래 걸린 경우
    except subprocess.TimeoutExpired:
        status = "TIMEOUT"

    # 실행 자체가 실패한 경우 (파일 깨짐 등)
    except Exception as e:
        status = f"ERROR:{e}"

    # 3. 로그 파일에 결과 기록
    with open(log_path, "a") as f:
        f.write(f"{label} | {status}\n")

    # 4. 비정상 케이스는 따로 저장 (크래시 수집)
    if "exit=0" not in status:
        os.makedirs(crash_dir, exist_ok=True)

        # 크래시 ELF 저장
        with open(f"{crash_dir}/{label}.elf", "wb") as f:
            f.write(elf_bytes)

    return status  # 호출한 쪽에서 결과 활용 가능