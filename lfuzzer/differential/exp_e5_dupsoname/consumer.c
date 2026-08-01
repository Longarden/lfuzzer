#include <stdio.h>
extern int exported_victim_value;
int main(void) {
    printf("exported_victim_value = %d\n", exported_victim_value);
    return 0;
}
