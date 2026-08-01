/* target_smc.c — self-modifying-code 시연 타깃
 * 베이스 빌드는 R-X 텍스트 → memcpy 시 SIGSEGV.
 * RWX 오버레이 적용 후에는 memcpy 성공 → 페이로드가 target_func 자리에서 실행됨.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int target_func(void) { return 1; }

int main(void)
{
    unsigned char payload[] = {
        0xb8, 0x2a, 0x00, 0x00, 0x00, /* mov $42, %eax */
        0xc3,                          /* ret           */
    };
    void *p = (void*)&target_func;
    printf("[smc] before memcpy: target_func()=%d at %p\n", target_func(), p);
    memcpy(p, payload, sizeof payload);
    int r = target_func();
    printf("[smc] after  memcpy: target_func()=%d\n", r);
    return r == 42 ? 0 : 99;
}
