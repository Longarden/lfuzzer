/* target_tls_auth.c — PT_TLS silent corruption 의 실용 시나리오.
 *
 * __thread 변수가 보안 결정에 쓰이는 경우를 모사.
 * - safety_locked 가 1 이면 safe path, 0 이면 위험 동작 (예: debug bypass)
 * - 정상 빌드: 초기값 1 → "ACCESS DENIED"
 * - PT_TLS 변형: TLS zero-init → 0 → "ACCESS GRANTED (debug bypass!)"
 *
 * iter23 F64 의 silent corruption 이 실제 보안 영향으로 이어지는 케이스.
 */
#include <stdio.h>

/* 안전 잠금 플래그. 정상 빌드에서는 1 (잠금). */
__thread int safety_locked = 1;

int main(void)
{
    if (safety_locked) {
        printf("ACCESS DENIED (safety_locked=%d)\n", safety_locked);
        return 0;
    } else {
        printf("ACCESS GRANTED (safety_locked=%d) -- DEBUG BYPASS\n", safety_locked);
        return 1;
    }
}
