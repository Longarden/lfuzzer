/* lib.c - trivial shared library with one exported function.
 * This is what libtest.so is built from. */
int get_answer(void) {
    return 42;
}
