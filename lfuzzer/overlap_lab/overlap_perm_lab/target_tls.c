/* target_tls.c — PT_TLS 슬롯을 위한 타깃.
 * __thread 변수가 있어야 컴파일러가 PT_TLS 세그먼트를 생성.
 *
 * 정상 출력: "TLS = 42\n"
 * PT_TLS 슬롯이 사라지거나 손상되면 TLS 변수 접근 시 SEGV / 잘못된 값.
 */
#include <stdio.h>

__thread int tls_var = 42;

int main(void)
{
    printf("TLS = %d\n", tls_var);
    return 0;
}
