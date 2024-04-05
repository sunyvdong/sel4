

#include <stdio.h>
#include <sel4/sel4.h>

extern seL4_CPtr endpoint;
extern seL4_CPtr reply;

int main(int c, char *argv[]) {

    printf("Server initialising\n");
    seL4_MessageInfo_t info = seL4_NBSendRecv(endpoint, info, endpoint, NULL, reply);
    while (1) {
        int i = 0;
        for (; i < seL4_MsgMaxLength && i < seL4_MessageInfo_get_length(info); i++) {
            seL4_DebugPutChar(seL4_GetMR(i));
        }
        seL4_DebugPutChar('\n');
        seL4_SetMR(0, i);
        info = seL4_ReplyRecv(endpoint, seL4_MessageInfo_new(0, 0, 0, i), NULL, reply);
    }

    return 0;
}