/* target_throw.cpp — PT_GNU_EH_FRAME 변환 후 C++ 예외 처리 동작 측정용.
 *
 * baseline: throw 후 catch 정상 동작, "caught: ..." 출력.
 * PT_GNU_EH_FRAME → PT_LOAD 변형: EH 정보 사라짐 → throw 시 unwinding 실패 → abort 또는 terminate.
 */
#include <cstdio>
#include <stdexcept>

int main()
{
    printf("[throw] before try\n");
    try {
        throw std::runtime_error("test exception");
    } catch (const std::exception& e) {
        printf("[throw] caught: %s\n", e.what());
    }
    printf("[throw] after try\n");
    return 0;
}
