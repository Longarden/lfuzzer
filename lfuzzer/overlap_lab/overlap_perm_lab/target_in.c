/* target_in.c — payload 를 별도 .payload 섹션 안에 미리 박아 둠.
 * file append 없이 (binary 안에 이미 존재) PHT overlay 로 텍스트 페이지에 매핑.
 */
#include <stdio.h>

__attribute__((section(".payload"), aligned(0x1000), used))
const unsigned char payload_block[0x1000] = {
    /* target_func 의 intra-page offset 자리에 mov $42; ret 박아둠.
     * intra-offset 은 build 후 측정해서 patch script 에서 보정. */
    [0x100] = 0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3,  /* placeholder slot 0x100 */
    [0x136] = 0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3,
    [0x150] = 0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3,
    [0x200] = 0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3,
};

int target_func(void) { return 1; }

int main(void)
{
    int r = target_func();
    printf("[in] result = %d\n", r);
    return r == 42 ? 0 : 99;
}
