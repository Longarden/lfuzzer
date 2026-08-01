/* target_probe.c — combo PoC 실증.
 * 1) printf@GOT 슬롯에 쓰기 시도 (baseline: SEGV, combo: 성공)
 * 2) 텍스트 페이지(0x401200) 쓰기 시도 (baseline: SEGV, combo: 성공)
 *
 * baseline: -no-pie -Wl,-z,relro -Wl,-z,now (full RELRO) → GOT RO, .text R-X.
 * combo 변형: PT_GNU_RELRO memsz 8B 줄임 + PT_NOTE→PT_LOAD RWX overlay.
 */
#include <unistd.h>
#include <stdint.h>
#include <string.h>

extern int printf(const char *, ...);

int main(void)
{
    write(1, "[probe] start\n", 14);

    /* target_probe 의 .got 는 0x403fc0~0x404000 (full RELRO 하에 R-only).
     * 안전한 슬롯 한 곳 (.got 안쪽 0x403fe0) 에 쓰기 시도. */
    void **got = (void**)0x403fe0;
    /* printf 심볼을 참조해서 .plt 와 .got 가 살아 있게 함 (사용 안 해도 됨) */
    (void)&printf;

    /* 1) GOT 슬롯 쓰기 — RELRO 가 적용된 baseline 에서는 SEGV */
    void *saved_got = *got;
    *got = saved_got;
    write(1, "[probe] GOT write OK\n", 21);

    /* 2) 텍스트 페이지 쓰기 — baseline 은 R-X 라 SEGV */
    volatile uint8_t *text = (uint8_t*)0x401200;
    uint8_t saved_t = *text;
    *text = saved_t;
    write(1, "[probe] text write OK\n", 22);

    write(1, "[probe] BOTH writes succeeded\n", 30);
    return 0;
}
