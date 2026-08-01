#!/bin/bash
# 사용자 복귀 후 sudo로 실행: 레인2(OSS-Fuzz 유저스페이스) + 차등도구 설치
set -e
echo "[1/4] 차등 파서 도구 설치 (eu-readelf 등)"
sudo apt-get update -qq && sudo apt-get install -y elfutils
pip install --user lief pyelftools 2>/dev/null || true

echo "[2/4] Docker 데몬 기동 (OSS-Fuzz 필수)"
sudo service docker start || sudo dockerd >/tmp/dockerd.log 2>&1 &
sleep 3; docker info >/dev/null 2>&1 && echo "  docker OK" || echo "  docker 실패 — Docker Desktop WSL통합 확인"

echo "[3/4] OSS-Fuzz 클론"
cd ~; [ -d oss-fuzz ] || git clone --depth 1 https://github.com/google/oss-fuzz
cd oss-fuzz

echo "[4/4] binutils ASAN 하네스 빌드 + 코퍼스 시드 재현"
python3 infra/helper.py build_fuzzers --sanitizer address binutils
# 대표 크래시를 하네스로 재현 (fuzz_disassemble/fuzz_bfd 등)
# python3 infra/helper.py reproduce binutils fuzz_bfd <크래시파일>
echo "완료. run: python3 infra/helper.py run_fuzzer binutils fuzz_bfd -- -runs=100000 <코퍼스디렉>"
