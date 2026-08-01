#include <stdio.h>
int g_counter = 0;
__thread int t_local = 7;
int foo_add(int a, int b){ g_counter++; return a+b+t_local; }
void foo_hello(void){ printf("hello from foo\n"); }
