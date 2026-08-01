/* main.c - trivial consumer that calls the exported symbol from libtest.so.
 * We only care whether LINKING succeeds (symbol resolution), so we don't
 * even need to run the resulting binary for the core experiment, though
 * the script will try to run it too, for extra evidence. */
#include <stdio.h>

int get_answer(void); /* declared in lib.c, defined in libtest*.so */

int main(void) {
    printf("answer=%d\n", get_answer());
    return 0;
}
