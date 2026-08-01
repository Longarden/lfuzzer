#!/bin/bash
# differential test inputs: main.o + libfoo.so (dynamic section를 조작할 대상)
set -e
D=/home/garden/PE/Lfuzzer/meeting_0714_step3/diff
mkdir -p $D; cd $D
cat > foo.c <<C
int foo_global = 42;
int foo(int x){ return x + foo_global; }
C
cat > main.c <<C
extern int foo(int);
int main(void){ return foo(1); }
C
gcc -fPIC -c foo.c -o foo.o
gcc -shared -Wl,-soname,libfoo.so.1 -o libfoo.so.1 foo.o
ln -sf libfoo.so.1 libfoo.so
gcc -c main.c -o main.o
echo "built: $(ls -la $D)"
