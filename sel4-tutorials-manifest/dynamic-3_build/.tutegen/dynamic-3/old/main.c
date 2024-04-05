
/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230).
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <autoconf.h>

#include <stdio.h>
#include <assert.h>

#include <sel4/sel4.h>

#include <simple/simple.h>
#include <simple-default/simple-default.h>

#include <vka/object.h>

#include <allocman/allocman.h>
#include <allocman/bootstrap.h>
#include <allocman/vka.h>

#include <vspace/vspace.h>

#include <sel4utils/vspace.h>
#include <sel4utils/mapping.h>
#include <sel4utils/process.h>

#include <utils/arith.h>
#include <utils/zf_log.h>
#include <sel4utils/sel4_zf_logif.h>

#include <sel4platsupport/bootinfo.h>

/* constants */
#define EP_BADGE 0x61 // arbitrary (but unique) number for a badge
#define MSG_DATA 0x6161 // arbitrary data to send

#define APP_PRIORITY seL4_MaxPrio
#define APP_IMAGE_NAME "app"

/* global environment variables */
seL4_BootInfo *info;
simple_t simple;
vka_t vka;
allocman_t *allocman;
vspace_t vspace;

/* static memory for the allocator to bootstrap with */
#define ALLOCATOR_STATIC_POOL_SIZE (BIT(seL4_PageBits) * 10)
UNUSED static char allocator_mem_pool[ALLOCATOR_STATIC_POOL_SIZE];

/* dimensions of virtual memory for the allocator to use */
#define ALLOCATOR_VIRTUAL_POOL_SIZE (BIT(seL4_PageBits) * 100)

/* static memory for virtual memory bootstrapping */
UNUSED static sel4utils_alloc_data_t data;

/* stack for the new thread */
#define THREAD_2_STACK_SIZE 4096
UNUSED static int thread_2_stack[THREAD_2_STACK_SIZE];

int main(void) {
    UNUSED int error = 0;

    /* get boot info */
    info = platsupport_get_bootinfo();
    ZF_LOGF_IF(info == NULL, "Failed to get bootinfo.");

    /* Set up logging and give us a name: useful for debugging if the thread faults */
    zf_log_set_tag_prefix("dynamic-3:");
    NAME_THREAD(seL4_CapInitThreadTCB, "dynamic-3");

    /* init simple */
    simple_default_init_bootinfo(&simple, info);

    /* print out bootinfo and other info about simple */
    simple_print(&simple);

    /* create an allocator */
    allocman = bootstrap_use_current_simple(&simple, ALLOCATOR_STATIC_POOL_SIZE,
                                            allocator_mem_pool);
    ZF_LOGF_IF(allocman == NULL, "Failed to initialize allocator.\n"
               "\tMemory pool sufficiently sized?\n"
               "\tMemory pool pointer valid?\n");

    /* create a vka (interface for interacting with the underlying allocator) */
    allocman_make_vka(&vka, allocman);

    
    /* TASK 1: create a vspace object to manage our vspace */
    /* hint 1: sel4utils_bootstrap_vspace_with_bootinfo_leaky()
     * int sel4utils_bootstrap_vspace_with_bootinfo_leaky(vspace_t *vspace, sel4utils_alloc_data_t *data, seL4_CPtr page_directory, vka_t *vka, seL4_BootInfo *info)
     * @param vspace Uninitialised vspace struct to populate.
     * @param data Uninitialised vspace data struct to populate.
     * @param page_directory Page directory for the new vspace.
     * @param vka Initialised vka that this virtual memory allocator will use to allocate pages and pagetables. This allocator will never invoke free.
     * @param info seL4 boot info
     * @return 0 on succes.
     */
    
    ZF_LOGF_IFERR(error, "Failed to prepare root thread's VSpace for use.\n"
                  "\tsel4utils_bootstrap_vspace_with_bootinfo reserves important vaddresses.\n"
                  "\tIts failure means we can't safely use our vaddrspace.\n");

    /* fill the allocator with virtual memory */
    void *vaddr;
    UNUSED reservation_t virtual_reservation;
    virtual_reservation = vspace_reserve_range(&vspace,
                                               ALLOCATOR_VIRTUAL_POOL_SIZE, seL4_AllRights, 1, &vaddr);
    ZF_LOGF_IF(virtual_reservation.res == NULL, "Failed to reserve a chunk of memory.\n");
    bootstrap_configure_virtual_pool(allocman, vaddr,
                                     ALLOCATOR_VIRTUAL_POOL_SIZE, simple_get_pd(&simple));

    
    /* TASK 2: use sel4utils to make a new process */
    /* hint 1: sel4utils_configure_process_custom()
     * hint 2: process_config_default_simple()
     * @param process Uninitialised process struct.
     * @param vka Allocator to use to allocate objects.
     * @param vspace Vspace allocator for the current vspace.
     * @param priority Priority to configure the process to run as.
     * @param image_name Name of the elf image to load from the cpio archive.
     * @return 0 on success, -1 on error.
     *
     * hint 2: priority is in APP_PRIORITY and can be 0 to seL4_MaxPrio
     * hint 3: the elf image name is in APP_IMAGE_NAME
     */
    sel4utils_process_t new_process;
    
    ZF_LOGF_IFERR(error, "Failed to spawn a new thread.\n"
                  "\tsel4utils_configure_process expands an ELF file into our VSpace.\n"
                  "\tBe sure you've properly configured a VSpace manager using sel4utils_bootstrap_vspace_with_bootinfo.\n"
                  "\tBe sure you've passed the correct component name for the new thread!\n");

    /* give the new process's thread a name */
    NAME_THREAD(new_process.thread.tcb.cptr, "dynamic-3: process_2");

    /* create an endpoint */
    vka_object_t ep_object = {0};
    error = vka_alloc_endpoint(&vka, &ep_object);
    ZF_LOGF_IFERR(error, "Failed to allocate new endpoint object.\n");

    /*
     * make a badged endpoint in the new process's cspace.  This copy
     * will be used to send an IPC to the original cap
     */

    
    /* TASK 3: make a cspacepath for the new endpoint cap */
    /* hint 1: vka_cspace_make_path()
     * void vka_cspace_make_path(vka_t *vka, seL4_CPtr slot, cspacepath_t *res)
     * @param vka Vka interface to use for allocation of objects.
     * @param slot A cslot allocated by the cspace alloc function
     * @param res Pointer to a cspacepath struct to fill out
     *
     * hint 2: use the cslot of the endpoint allocated above
     */
    cspacepath_t ep_cap_path;
    seL4_CPtr new_ep_cap = 0;
    

    
    /* TASK 4: copy the endpont cap and add a badge to the new cap */
    /* hint 1: sel4utils_mint_cap_to_process()
     * seL4_CPtr sel4utils_mint_cap_to_process(sel4utils_process_t *process, cspacepath_t src, seL4_CapRights rights, seL4_Word data)
     * @param process Process to copy the cap to
     * @param src Path in the current cspace to copy the cap from
     * @param rights The rights of the new cap
     * @param data Extra data for the new cap (e.g., the badge)
     * @return 0 on failure, otherwise the slot in the processes cspace.
     *
     * hint 2: for the rights, use seL4_AllRights
     * hint 3: for the badge value use EP_BADGE
     */
    

    ZF_LOGF_IF(new_ep_cap == 0, "Failed to mint a badged copy of the IPC endpoint into the new thread's CSpace.\n"
               "\tsel4utils_mint_cap_to_process takes a cspacepath_t: double check what you passed.\n");

    printf("NEW CAP SLOT: %" PRIxPTR ".\n", ep_cap_path.capPtr);


    
    /* TASK 5: spawn the process */
    /* hint 1: sel4utils_spawn_process_v()
     * int sel4utils_spawn_process_v(sel4utils_process_t *process, vka_t *vka, vspace_t *vspace, int argc, char *argv[], int resume)
     * @param process Initialised sel4utils process struct.
     * @param vka Vka interface to use for allocation of frames.
     * @param vspace The current vspace.
     * @param argc The number of arguments.
     * @param argv A pointer to an array of strings in the current vspace.
     * @param resume 1 to start the process, 0 to leave suspended.
     * @return 0 on success, -1 on error.
     */
    /* hint 2: sel4utils_create_word_args()
     * void sel4utils_create_word_args(char strings[][WORD_STRING_SIZE], char *argv[], int argc, ...)
     * Create c-formatted argument list to pass to a process from arbitrarily long amount of words.
     *
     * @param strings empty 2d array of chars to populate with word strings.
     * @param argv empty 1d array of char pointers which will be set up with pointers to
     *             strings in strings.
     * @param argc number of words
     * @param ... list of words to create arguments from.
     *
     */
    
    ZF_LOGF_IFERR(error, "Failed to spawn and start the new thread.\n"
                  "\tVerify: the new thread is being executed in the root thread's VSpace.\n"
                  "\tIn this case, the CSpaces are different, but the VSpaces are the same.\n"
                  "\tDouble check your vspace_t argument.\n");

    /* we are done, say hello */
    printf("main: hello world\n");

    /*
     * now wait for a message from the new process, then send a reply back
     */

    seL4_Word sender_badge = 0;
    seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 0);
    seL4_Word msg;

    
    /* TASK 6: wait for a message */
    /* hint 1: seL4_Recv()
     * seL4_MessageInfo_t seL4_Recv(seL4_CPtr src, seL4_Word* sender)
     * @param src The capability to be invoked.
     * @param sender The badge of the endpoint capability that was invoked by the sender is written to this address.
     * @return A seL4_MessageInfo_t structure
     *
     * hint 2: seL4_MessageInfo_t is generated during build.
     * hint 3: use the badged endpoint cap that you minted above
     */
    
   /* make sure it is what we expected */
    ZF_LOGF_IF(sender_badge != EP_BADGE,
               "The badge we received from the new thread didn't match our expectation.\n");

    ZF_LOGF_IF(seL4_MessageInfo_get_length(tag) != 1,
               "Response data from the new process was not the length expected.\n"
               "\tHow many registers did you set with seL4_SetMR within the new process?\n");


    /* get the message stored in the first message register */
    msg = seL4_GetMR(0);
    printf("main: got a message %#" PRIxPTR " from %#" PRIxPTR "\n", msg, sender_badge);

    /* modify the message */
    seL4_SetMR(0, ~msg);

    
    /* TASK 7: send the modified message back */
    /* hint 1: seL4_ReplyRecv()
     * seL4_MessageInfo_t seL4_ReplyRecv(seL4_CPtr dest, seL4_MessageInfo_t msgInfo, seL4_Word *sender)
     * @param dest The capability to be invoked.
     * @param msgInfo The messageinfo structure for the IPC.  This specifies information about the message to send (such as the number of message registers to send) as the Reply part.
     * @param sender The badge of the endpoint capability that was invoked by the sender is written to this address. This is a result of the Wait part.
     * @return A seL4_MessageInfo_t structure.  This is a result of the Wait part.
     *
     * hint 2: seL4_MessageInfo_t is generated during build.
     * hint 3: use the badged endpoint cap that you used for Call
     */
    


    return 0;
}