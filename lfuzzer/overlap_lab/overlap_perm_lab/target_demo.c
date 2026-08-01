/* target_demo.c — 미팅 발표용 단일 출력 분기 DEMO.
 *
 * baseline: magic() returns 1 → "Hello, ELF World!"
 * combo 변형: PHT 패치로 magic() 자리에 mov $42; ret 박힘 → "Hello from Combo World!"
 *
 * 빌드/소스/심볼/sha256 차이 외에는 readelf -l 의 PT_LOAD 한 줄만 다름.
 */
#include <stdio.h>

int magic(void) { return 1; }

int main(void)
{
    int m = magic();
    if (m == 42)
        printf("Hello from Combo World!\n");
    else
        printf("Hello, ELF World!\n");
    return 0;
}
