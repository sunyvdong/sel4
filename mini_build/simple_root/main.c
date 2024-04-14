#include <sel4/sel4.h>
#include <sel4runtime.h>

int main(int argc, char *argv[])
{
    seL4_BootInfo *info = sel4runtime_bootinfo();

    seL4_CPtr first_free_slot = info->empty.start;
    seL4_Error error = seL4_CNode_Copy(seL4_CapInitThreadCNode, first_free_slot, seL4_WordBits,
                                       seL4_CapInitThreadCNode, seL4_CapInitThreadTCB, seL4_WordBits,
                                       seL4_AllRights);
    while (1) {
        /* code */
    }
    return 0;
}