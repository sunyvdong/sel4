/*
 * Copyright 2018, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>
#include <utils/util.h>


#define DECLARE_IPCBUFFER_SYMBOL(symbol) \
extern char symbol[]; \
void CONSTRUCTOR(199) setIPCBuffer(void) { \
    __sel4_ipc_buffer = (seL4_IPCBuffer *) symbol;\
}


DECLARE_IPCBUFFER_SYMBOL(mainIpcBuffer)

#define SIZED_SYMBOL(symbol, size, section) \
	char symbol[size] VISIBLE ALIGN(4096) SECTION(section);

seL4_CPtr endpoint = 1;
seL4_CPtr ntfn = 2;
seL4_CPtr device_untyped = 3;
seL4_CPtr timer_frame = 4;
seL4_CPtr cnode = 5;
seL4_CPtr vspace = 6;
seL4_CPtr frame = 7;
seL4_CPtr irq_control = 8;
seL4_CPtr irq_handler = 9;


SIZED_SYMBOL(timer_vaddr, 4096, "size_12bit")
SIZED_SYMBOL(stack, 65536, "size_12bit")
SIZED_SYMBOL(mainIpcBuffer, 4096, "size_12bit")



char progname[] = "timer";