#include <stdio.h>

/* Internal implementation under a distinct name so .symver can alias
 * it to the public versioned name foo@@VERS_1.0 (aliasing a symbol to
 * its own literal name causes a multiple-definition error).
 *
 * foo_impl() calls printf() so linking libv.so pulls in a real
 * *versioned* glibc symbol (printf@GLIBC_2.x). That is what forces
 * the linker to emit a genuine, non-empty .gnu.version_r (Verneed)
 * table referencing glibc's version definitions -- the table this
 * experiment corrupts.
 */
int foo_impl(void) {
    printf("hello from foo\n");
    return 42;
}
__asm__(".symver foo_impl,foo@@VERS_1.0");
