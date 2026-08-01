/* References foo() so the linker must pull in libv_corrupt.so as a
 * NEEDED shared object and parse its .gnu.version_r table.
 */
extern int foo(void);
int callfoo(void) { return foo(); }
