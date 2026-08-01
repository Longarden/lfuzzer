# iter25 — phdr 변환 통합 비교 매트릭스

| PHDR type | baseline | exit | text@0x401 | silent corruption | 원본 마커 사라짐 | PT_LOAD count | detector v3 |
|---|---|---|---|---|---|---|---|
| PT_NOTE | target_partial | 0 | rwxp | No | False | 4→5 | ANOMALY |
| PT_GNU_EH_FRAME | target_full | 0 | rwxp | No | True | 4→5 | ANOMALY |
| PT_GNU_PROPERTY | target_full | 0 | rwxp | No | True | 4→5 | ANOMALY |
| PT_TLS | target_tls | 0 | rwxp | **Yes (TLS=42→0)** | True | 4→5 | ANOMALY |
| PT_GNU_STACK | target_full | 0 | rwxp | No | True | 4→5 | ANOMALY |

## 결론
- 5개 phdr 타입 전부 PT_LOAD RWX 변환 가능, 텍스트 페이지가 RWX 로 떨어지고 main 도달.
- **PT_TLS 만 유일하게 silent corruption** (TLS 변수 42→0). 다른 4종은 functional 영향 없음.
- 5종 모두 detector v3 가 ANOMALY 로 잡음 (phdr 타입 무관 vaddr 오버랩 시그널 동작).
- PT_NOTE/PROPERTY/EH_FRAME/STACK 의 원본 마커는 readelf -l 에서 사라짐 → 정적 분석기 단서 1.
- 가장 stealth + 실용적인 변형: **PT_GNU_EH_FRAME** — 어느 ELF 든 항상 존재, 보호 메타 아닌 디버그 메타라 분석가 우선 순위 낮음, 변환 효과 PT_NOTE 와 동일.
- 가장 위험한 변형: **PT_TLS** — silent corruption 으로 데이터 무결성 깨짐 (예: ID/key 변수가 0 으로). 단 TLS 사용 바이너리에 한정.