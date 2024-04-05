

#include <stdio.h>
#include <sel4/sel4.h>
#include <utils/util.h>

int main(int c, char *argv[]) {

    int i = 0;
    while (1) {
        printf("Yield\n");
        seL4_Yield();
    }
    return 0;
}