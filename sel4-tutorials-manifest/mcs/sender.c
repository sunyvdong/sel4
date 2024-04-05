

#include <stdio.h>
#include <sel4/sel4.h>

extern seL4_CPtr endpoint;
int main(int c, char *argv[]) {
    int i = 0;
    while (1) {
        seL4_MessageInfo_t info = seL4_MessageInfo_new(0, 0, 0, 1);
        seL4_SetMR(0, i);
        seL4_Send(endpoint, info);
        i++;
    }
    return 0;
}