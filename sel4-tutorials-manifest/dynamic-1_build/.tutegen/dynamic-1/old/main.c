
/*
 * Copyright 2018, Data61, CSIRO (ABN 41 687 119 230).
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * seL4 tutorial part 2: create and run a new thread
 */

/* Include config variables. */
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

#include <utils/arith.h>
#include <utils/zf_log.h>
#include <sel4utils/sel4_zf_logif.h>
#include <sel4utils/thread.h>

#include <sel4platsupport/bootinfo.h>

/* global environment variables */

/* seL4_BootInfo defined in bootinfo.h */
seL4_BootInfo *info;

/* simple_t defined in simple.h */
simple_t simple;

/* vka_t defined in vka.h */
vka_t vka;

/* allocman_t defined in allocman.h */
allocman_t *allocman;

/* static memory for the allocator to bootstrap with */
#define ALLOCATOR_STATIC_POOL_SIZE (BIT(seL4_PageBits) * 10)
UNUSED static char allocator_mem_pool[ALLOCATOR_STATIC_POOL_SIZE];

/* stack for the new thread */
#define THREAD_2_STACK_SIZE 512
static uint64_t thread_2_stack[THREAD_2_STACK_SIZE];

/* function to run in the new thread */
void thread_2(void) {
    
    /* TASK 15: print something */
    /* hint: printf() */
    
    /* never exit */
    while (1);
}

int main(void) {
    UNUSED int error = 0;

    
    /* TASK 1: get boot info */
    /* hint: platsupport_get_bootinfo()
     * seL4_BootInfo* platsupport_get_bootinfo(void);
     * @return Pointer to the bootinfo, NULL on failure
     */
    
    ZF_LOGF_IF(info == NULL, "Failed to get bootinfo.");

    /* Set up logging and give us a name: useful for debugging if the thread faults */
    /* seL4_CapInitThreadTCB is a cap pointer to the root task's initial TCB.
     * It is part of the root task's boot environment and defined in bootinfo.h from libsel4:
     * https://docs.sel4.systems/Tutorials/seL4_Tutorial_2#globals-links:
     */
    zf_log_set_tag_prefix("dynamic-1:");
    NAME_THREAD(seL4_CapInitThreadTCB, "dynamic-1");

    
   /* TASK 2: initialise simple object */
   /* hint: simple_default_init_bootinfo()
    * void simple_default_init_bootinfo(simple_t *simple, seL4_BootInfo *bi);
    * @param simple Structure for the simple interface object. This gets initialised.
    * @param bi Pointer to the bootinfo describing what resources are available
    */
    

    
    /* TASK 3: print out bootinfo and other info about simple */
    /* hint: simple_print()
     * void simple_print(simple_t *simple);
     * @param simple Pointer to simple interface.
     */
    

    
    /* TASK 4: create an allocator */
    /* hint: bootstrap_use_current_simple()
     * allocman_t *bootstrap_use_current_simple(simple_t *simple, uint32_t pool_size, char *pool);
     * @param simple Pointer to simple interface.
     * @param pool_size Size of the initial memory pool.
     * @param pool Initial memory pool.
     * @return returns NULL on error
     */
    
    ZF_LOGF_IF(allocman == NULL, "Failed to initialize alloc manager.\n"
               "\tMemory pool sufficiently sized?\n"
               "\tMemory pool pointer valid?\n");

    
    /* TASK 5: create a vka (interface for interacting with the underlying allocator) */
    /* hint: allocman_make_vka()
     * void allocman_make_vka(vka_t *vka, allocman_t *alloc);
     * @param vka Structure for the vka interface object.  This gets initialised.
     * @param alloc allocator to be used with this vka
     */
    

    
    /* TASK 6: get our cspace root cnode */
    /* hint: simple_get_cnode()
     * seL4_CPtr simple_get_cnode(simple_t *simple);
     * @param simple Pointer to simple interface.
     * @return The cnode backing the simple interface. no failure.
     */
    seL4_CPtr cspace_cap;
    

    
    /* TASK 7: get our vspace root page diretory */
    /* hint: simple_get_pd()
     * seL4_CPtr simple_get_pd(simple_t *simple);
     * @param simple Pointer to simple interface.
     * @return The vspace (PD) backing the simple interface. no failure.
     */
    seL4_CPtr pd_cap;
    

    
    /* TASK 8: create a new TCB */
    /* hint: vka_alloc_tcb()
     * int vka_alloc_tcb(vka_t *vka, vka_object_t *result);
     * @param vka Pointer to vka interface.
     * @param result Structure for the TCB object.  This gets initialised.
     * @return 0 on success
     */
    vka_object_t tcb_object = {0};
    
    ZF_LOGF_IFERR(error, "Failed to allocate new TCB.\n"
                  "\tVKA given sufficient bootstrap memory?");

    
   /* TASK 9: initialise the new TCB */
    /* hint 1: seL4_TCB_Configure()
     * int seL4_TCB_Configure(seL4_TCB _service, seL4_Word fault_ep, seL4_CNode cspace_root, seL4_Word cspace_root_data, seL4_CNode vspace_root, seL4_Word vspace_root_data, seL4_Word buffer, seL4_CPtr bufferFrame)
     * @param service Capability to the TCB which is being operated on.
     * @param fault_ep Endpoint which receives IPCs when this thread faults (must be in TCB's cspace).
     * @param cspace_root The new CSpace root.
     * @param cspace_root_data Optionally set the guard and guard size of the new root CNode. If set to zero, this parameter has no effect.
     * @param vspace_root The new VSpace root.
     * @param vspace_root_data Has no effect on IA-32 or ARM processors.
     * @param buffer Address of the thread's IPC buffer. Must be 512-byte aligned. The IPC buffer may not cross a page boundary.
     * @param bufferFrame Capability to a page containing the thread?s IPC buffer.
     * @return 0 on success.
     * Note: this function is generated during build.  It is generated from the following definition:
     *
     * hint 2: use seL4_CapNull for the fault endpoint
     * hint 3: use seL4_NilData for cspace and vspace data
     * hint 4: we don't need an IPC buffer frame or address yet
     */
    
    ZF_LOGF_IFERR(error, "Failed to configure the new TCB object.\n"
                  "\tWe're running the new thread with the root thread's CSpace.\n"
                  "\tWe're running the new thread in the root thread's VSpace.\n"
                  "\tWe will not be executing any IPC in this app.\n");

    /* Set the priority of the new thread to be equal to our priority. This ensures it will run
     * in round robin with us. By default it has priority of 0 and so would never run unless we block */
    error = seL4_TCB_SetPriority(tcb_object.cptr, simple_get_tcb(&simple), 255);
    ZF_LOGF_IFERR(error, "Failed to set the priority for the new TCB object.\n");

    
    /* TASK 10: give the new thread a name */
    /* hint: we've done thread naming before */
    

    
    /*
     * set start up registers for the new thread:
     */
    UNUSED seL4_UserContext regs = {0};

    /* TASK 11: set instruction pointer where the thread shoud start running */
    /* hint 1: sel4utils_set_instruction_pointer()
     * void sel4utils_set_instruction_pointer(seL4_UserContext *regs, seL4_Word value);
     * @param regs Data structure in which to set the instruction pointer value
     * @param value New instruction pointer value
     *
     * hint 2: we want the new thread to run the function "thread_2"
     */
    

    /* check that stack is aligned correctly */
    const int stack_alignment_requirement = sizeof(seL4_Word) * 2;
    uintptr_t thread_2_stack_top = (uintptr_t)thread_2_stack + sizeof(thread_2_stack);
    ZF_LOGF_IF(thread_2_stack_top % (stack_alignment_requirement) != 0,
               "Stack top isn't aligned correctly to a %dB boundary.\n"
               "\tDouble check to ensure you're not trampling.",
               stack_alignment_requirement);

    
    /* TASK 12: set stack pointer for the new thread */
    /* hint 1: sel4utils_set_stack_pointer()
     * void sel4utils_set_stack_pointer(seL4_UserContext *regs, seL4_Word value);
     * @param regs  Data structure in which to set the stack pointer value
     * @param value New stack pointer value
     *
     * hint 2: remember the stack grows down!
     */
    

    
    /* TASK 13: actually write the TCB registers.  We write 2 registers:
     * instruction pointer is first, stack pointer is second. */
    /* hint: seL4_TCB_WriteRegisters()
     * int seL4_TCB_WriteRegisters(seL4_TCB service, seL4_Bool resume_target, seL4_Uint8 arch_flags, seL4_Word count, seL4_UserContext *regs)
     * @param service Capability to the TCB which is being operated on.
     * @param resume_target The invocation should also resume the destination thread.
     * @param arch_flags Architecture dependent flags. These have no meaning on either IA-32 or ARM.
     * @param count The number of registers to be set.
     * @param regs Data structure containing the new register values.
     * @return 0 on success
     */
    
    ZF_LOGF_IFERR(error, "Failed to write the new thread's register set.\n"
                  "\tDid you write the correct number of registers? See arg4.\n");

    
    /* TASK 14: start the new thread running */
    /* hint: seL4_TCB_Resume()
     * int seL4_TCB_Resume(seL4_TCB service)
     * @param service Capability to the TCB which is being operated on.
     * @return 0 on success
     */
    
    ZF_LOGF_IFERR(error, "Failed to start new thread.\n");
    /* we are done, say hello */
    printf("main: hello world\n");

    return 0;
}