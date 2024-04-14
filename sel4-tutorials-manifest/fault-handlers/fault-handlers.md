<!--
  Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)

  SPDX-License-Identifier: BSD-2-Clause
-->

# Fault handling


## Prerequisites

1. [Set up your machine](https://docs.sel4.systems/HostDependencies).
2. [Capabilities tutorial](https://docs.sel4.systems/Tutorials/capabilities).
3. [IPC Tutorial](https://docs.sel4.systems/Tutorials/ipc).

## Initialising

```sh
# For instructions about obtaining the tutorial sources see https://docs.sel4.systems/Tutorials/#get-the-code
#
# Follow these instructions to initialise the tutorial
# initialising the build directory with a tutorial exercise
./init --tut fault-handlers
# building the tutorial exercise
cd fault-handlers_build
ninja
```


## Outcomes

1. Learn what a thread fault is.
2. Understand that a thread fault is different from a processor hardware fault.
3. Learn what a fault handler is.
4. Understand what the kernel does to a thread which has faulted.
5. Learn how to set the endpoint that the kernel will deliver fault messages on (master vs MCS).
6. Learn how to resume threads after they have faulted.

## Background: What is a fault, and what is a fault handler?

A fault handler is a separate instruction stream which the CPU can jump to in
order to rectify an anomalous condition in the current thread and then return to
the previous instruction stream.

In seL4, faults are modeled as separately programmer-designated "fault handler"
threads. In monolithic kernels, faults are not usually delivered to a userspace
handler, but they are handled by the monolithic kernel itself.

In general, attempting to resume execution of the faulted thread
without rectifying the anomaly will simply re-trigger the fault ad infinitum
until the anomaly is cleared away.

## Thread faults vs other sources of faults

There are several sources of faults in a running system; they include:
* Fault events generated by the CPU itself when it encounters anomalies in the instruction stream (aka, "processor exceptions").
* Fault events generated by hardware in the event of some hardware anomaly (such as a machine check or non-maskable interrupt).
* Fault events generated by the seL4 kernel when it encounters anomalies in the current thread.

This tutorial is only concerned with those fault events generated by the seL4
kernel. We will call them "thread faults" from here onward to reduce ambiguity.

## How does thread fault handling work?

In seL4, when a thread generates a thread fault, the kernel will **block** the
faulting thread's execution and attempt to deliver a message across a special
endpoint associated with that thread, called its "fault handler" endpoint.

The only special thing about the fault handler endpoint is that a thread can
only have *one* of them. Otherwise it is created and managed just the same way
as any other kind of seL4 endpoint object.

The thread which is listening on the other end of the fault endpoint is called
the "fault handler". The kernel expects that the fault handler will correct the
anomaly that ails the faulting thread and then tell the kernel when it is safe
to try executing the faulting thread once again.

To tell the kernel to resume execution of the faulting thread, the fault handler
can either:
* Invoke a reply operation (with `seL4_Reply()`) on the fault handler endpoint and make sure that the `label` in the `seL4_MessageInfo_t` tag is set to `0`;
* Explicitly tell the kernel to resume executing the faulting thread using `seL4_TCB_Resume()`.

Please note that if the `handler` sets message registers in the reply message,
the kernel may interpret these as meaning something: some fault replies accept
parameters. See the seL4 manual for the reply message format for all faults.

If the fault handler did not properly rectify the anomaly in the faulting
thread, resuming the faulting thread will simply cause the kernel to re-generate
the fault.

## Reasons for thread faults:

Thread faults can be generated for different reasons. When a fault occurs the
kernel will pass information describing the cause of the fault as an IPC
message. At the time of writing, the following faults could be generated by
the Master version of the seL4 kernel:

* Cap fault: A fault triggered because of an invalid cap access.
* VM fault: A fault triggered by incoherent page table state or incorrect memory accesses by a thread.
* Unknown Syscall fault: Triggered by performing a syscall invocation that is unknown to the kernel.
* Debug fault: Triggered when a breakpoint, watchpoint or single-step debug event occurs.

In addition, the following fault types are added by the MCS kernel:

* Timeout fault: Triggered when a thread consumes all of its budget and still has further execution to do in the current period.

## Thread fault messages:

When a fault is generated, the kernel will deliver an IPC message across the
fault endpoint. This IPC message contains information that tells the fault
handler why the fault occured as well as surrounding contextual information
about the fault which might help the fault handler to rectify the anomaly.

Each anomaly has its own message format because the information needed to
describe each anomaly will be different. For more information about the contents
of the IPC message sent by the seL4 kernel for each fault anomaly, please see
the [seL4 Manual](https://sel4.systems/Info/Docs/seL4-manual-latest.pdf).

The rest of this tutorial will attempt to teach the reader how to receive and
handle seL4 thread faults.

## Setting up a fault endpoint for a thread:

In the scenario where a fault message is being delivered on a fault endpoint,
the kernel acts as the IPC "sender" and the fault handler acts as a receiver.

This implies that when caps are being handed out to the fault endpoint object,
one cap to the object must be given to the kernel and one cap to the object must
be given to the handler.

### Kernel end vs handler end:

Programmers specify the capability to use a fault handler for a thread when
configuring a TCB. As a result the programmer can also set a badge on the
kernel's cap to the fault endpoint object.

When the kernel sends a fault IPC message using a badged endpoint cap, the badge
is delivered to the receiver just the same way it is delivered for any other
IPC where there is a badge on the sender's cap.

A keen reader would probably have realized that this means that a badge on the
kernel's cap to a fault endpoint can be used to distinguish fault messages
from different faulting threads, such that a single handler can handle
faults from multiple threads. Please see the
[IPC Tutorial](https://docs.sel4.systems/Tutorials/ipc) for a refresher on how
badged fault endpoints work.

### Differences between MCS and Master kernel:

There is a minor difference in the way that the kernel is informed of the
cap to a fault endpoint, between the master and MCS kernels.

Regardless though, on both versions of the kernel, to inform the kernel of the
fault endpoint for a thread, call the usual `seL4_TCB_SetSpace()`.

See the [MCS tutorial](https://docs.sel4.systems/Tutorials/mcs.html) for more information.

## Exercises

This tutorial has one address space set up by the CapDL loader, containing two
threads which share the same CSpace. One of the threads is a fault handler while
the other triggers a virtual memory fault.

You will be guided through the following broad steps:
1. Badging and configuring a fault handler for the faulting thread.
2. Having the faulting thread trigger a thread fault.
3. Handling the fault in the fault handler.
4. Resuming the execution of the faulting thread.

### Description of the tutorial program:

The tutorial features two threads in different virtual address spaces. One
thread is the "`faulter`" and the other is the "`handler`". The `faulter` is going to
generate a fault, and the `handler` will "handle" it.

In order for the `handler` to handle the fault, the `handler` must set up a
fault-handling endpoint and tell the kernel to send all fault IPC messages
generated by the `faulter` thread to itself. This is therefore the first step we
take.

However, we have to ensure that the fault is only triggered *after* the `handler`
thread has set up the fault-handling endpoint and is ready to receive the fault
IPC message from the kernel.

If the `faulter` thread generates a fault and there is no thread to handle the
the IPC message, the kernel will simply suspend the `faulting` thread.

For this reason we make the `faulter` thread `seL4_call()` the `handler` thread
across an endpoint and tell it which slot the `handler` should place the fault
handling endpoint cap into. After the `handler` has set up the handler endpoint,
the `handler` will `seL4_Reply()` to the `faulter` to let it know that it the
`handler` is ready to handle fault IPC messages.

After that we trigger a fault in the `faulter`, handle the fault in the `handler`,
and then resume the `faulter` and that's the end of the exercise.

### Setting up the endpoint to be used for thread fault IPC messages.

The first exercise is to configure the TCB of the faulter with a fault endpoint.
This exercise is meant to achieve two learning outcomes:
1. Explain that the end of the endpoint that is given to the kernel can be badged, and the kernel will return that badge value when it sends a fault IPC message.
2. Explain the differences between the Master and MCS kernels when it comes to telling the kernel about the fault endpoint.

Right now the `faulter` thread is blocked on an Endpoint, waiting for the `handler`
to tell it where to put the fault handler endpoint within its own (the
`faulter`'s) CSpace (for the Master kernel).

To set up the fault handler endpoint, we will to first badge it so that when the
kernel sends us a fault IPC message, we will be able to identify the faulter.
Fault handlers can handle faults from multiple threads, so a badge
enables handlers to identify the faulters they are handling.

To badge the endpoint, use the `seL4_CNode_Mint()` syscall:

```c
    error = seL4_CNode_Mint(
        handler_cspace_root,
        badged_faulter_fault_ep_cap,
        seL4_WordBits,
        handler_cspace_root,
        faulter_fault_ep_cap,
        seL4_WordBits,
        seL4_AllRights, FAULTER_BADGE_VALUE);
```

Since we are using the Master kernel, you will also need to copy the badged cap
into the `faulter`'s CSpace (See the [MCS tutorial](https://docs.sel4.systems/Tutorials/mcs.html)
for an explanation of the differences between the Master and MCS kernel when
configuring fault endpoints):

```c
    error = seL4_CNode_Copy(
        faulter_cspace_root,
        foreign_badged_faulter_empty_slot_cap,
        seL4_WordBits,
        handler_cspace_root,
        badged_faulter_fault_ep_cap,
        seL4_WordBits,
        seL4_AllRights);
```

Finally, we tell the kernel the cap address of the fault endpoint so that the
kernel can deliver fault IPC messages to the `handler`. Since we're
using the Master kernel, we need to pass a CPtr that can be resolved from within
the CSpace of the `faulter` thread:

```c
    error = seL4_TCB_SetSpace(
        faulter_tcb_cap,
        foreign_badged_faulter_empty_slot_cap,
        faulter_cspace_root,
        0,
        faulter_vspace_root,
        0);
```

### Receiving the IPC message from the kernel:

The kernel will deliver the IPC message to any thread waiting on the fault
endpoint. To wait for a fault IPC message simply `seL4_Recv()`, the same way
you'd wait for any other IPC message:

```c
    foreign_faulter_capfault_cap = seL4_GetMR(seL4_CapFault_Addr);
```

### Finding out information about the generated thread fault:

In the thread fault IPC message, the kernel will send information about the
fault including the capability address whose access triggered the thread fault.
The seL4 manual gives detailed information on which message registers in the IPC
buffer contain information about the fault and if you're so inclined, the
libsel4 source code also has the exact code values as well.

In our example here, our sample code generated a Cap Fault, so according to the
seL4 manual, we can find out the cap fault address using at offset
`seL4_CapFault_Addr` in the IPC message, as you see above in the code snippet.

### Handling a thread fault:

Now that we know the cap address that generated a fault in the `faulting` thread,
we can "handle" the fault by putting a random cap into that slot and then when
the `faulter` thread re-tries to access that slot, it will succeed this time and
no thread fault will be generated.

So here we'll copy an endpoint cap into the faulting slot:

```c
    error = seL4_CNode_Copy(
        faulter_cspace_root,
        foreign_faulter_capfault_cap,
        seL4_WordBits,
        handler_cspace_root,
        sequencing_ep_cap,
        seL4_WordBits,
        seL4_AllRights);
```

### Resuming a faulting thread:

Finally, to have the `faulter` thread wake up and try to execute again, we
`seL4_Reply()` to it:

```c
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
```

## Further exercises

If you'd like to challenge yourself, make sure to set up the fault handling on
both versions of the kernel: master and MCS.


---
## Getting help
Stuck? See the resources below.
* [FAQ](https://docs.sel4.systems/FrequentlyAskedQuestions)
* [seL4 Manual](http://sel4.systems/Info/Docs/seL4-manual-latest.pdf)
* [Debugging guide](https://docs.sel4.systems/DebuggingGuide.html)
* [seL4 Discourse forum](https://sel4.discourse.group)
* [Developer's mailing list](https://lists.sel4.systems/postorius/lists/devel.sel4.systems/)
* [Mattermost Channel](https://mattermost.trustworthy.systems/sel4-external/)