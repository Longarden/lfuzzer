/* libA.c merely calls into libC; it does not re-export c_func under
   its own name, so anything that wants c_func must transitively reach
   libC.so through libA.so's DT_NEEDED entry. */
extern int c_func(void);
int a_helper(void) { return c_func() + 1; }
