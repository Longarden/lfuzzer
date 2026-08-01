/* target_probe_demo.c — target_probe 의 클린 버전.
 * baseline: GOT 쓰기 시도에서 SEGV (출력 없음).
 * combo 변형 (RELRO shrink + RWX overlay): 한 줄 "Hello from Pwned World!" 출력.
 *
 * target_probe 와 다른 점: 진단 메시지 4줄 → 출력 1줄로 단순화.
 */
#include <unistd.h>
#include <stdint.h>

extern int printf(const char *, ...);

int main(void)
{
    /* printf 심볼 살리기 위한 참조 (호출은 아래 한 번만) */
    (void)&printf;

    /* .got 안쪽 슬롯에 same-value write — full RELRO 적용 시 SEGV */
    void **got = (void**)0x403fe0;
    *got = *got;

    /* 텍스트 페이지에 same-byte write — R-X 면 SEGV */
    volatile uint8_t *text = (uint8_t*)0x401200;
    *text = *text;

    printf("Hello from Pwned World!\n");
    return 0;
}
