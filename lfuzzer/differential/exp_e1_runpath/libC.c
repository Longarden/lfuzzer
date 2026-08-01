/* libC exports one symbol. This is the library that must be found
   ONLY through libA.so's own DT_RUNPATH. */
int c_func(void) { return 42; }
