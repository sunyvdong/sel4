/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/*
 * This file is autogenerated by <kernel>/tools/hardware/outputs/c_header.py.
 */

#pragma once

#define PHYS_BASE_RAW 0x40000000

#ifndef __ASSEMBLER__

#include <config.h>
#include <mode/hardware.h>  /* for KDEV_BASE */
#include <linker.h>         /* for BOOT_RODATA */
#include <basic_types.h>    /* for p_region_t, kernel_frame_t (arch/types.h) */

/* Wrap raw physBase location constant to give it a symbolic name in C that's
 * visible to verification. This is necessary as there are no real constants
 * in C except enums, and enums constants must fit in an int.
 */
static inline CONST word_t physBase(void)
{
    return PHYS_BASE_RAW;
}

/* INTERRUPTS */
/* INTERRUPT_VTIMER_EVENT generated from /timer */
#define INTERRUPT_VTIMER_EVENT 27
/* KERNEL_TIMER_IRQ generated from /timer */
#ifdef CONFIG_ARM_HYPERVISOR_SUPPORT
#define KERNEL_TIMER_IRQ 26
#else
#define KERNEL_TIMER_IRQ 27
#endif /* CONFIG_ARM_HYPERVISOR_SUPPORT */
/* KERNEL DEVICES */
#define UART_PPTR (KDEV_BASE + 0x0)
#define GIC_V2_DISTRIBUTOR_PPTR (KDEV_BASE + 0x1000)
#define GIC_V2_CONTROLLER_PPTR (KDEV_BASE + 0x2000)

static const kernel_frame_t BOOT_RODATA kernel_device_frames[] = {
    #ifdef CONFIG_PRINTING
    /* /pl011@9000000 */
    {
        .paddr = 0x9000000,
        .pptr = UART_PPTR,
        .armExecuteNever = true,
        .userAvailable = true
    },
    #endif /* CONFIG_PRINTING */
    /* /intc@8000000 */
    {
        .paddr = 0x8000000,
        .pptr = GIC_V2_DISTRIBUTOR_PPTR,
        .armExecuteNever = true,
        .userAvailable = false
    },
    /* /intc@8000000 */
    {
        .paddr = 0x8010000,
        .pptr = GIC_V2_CONTROLLER_PPTR,
        .armExecuteNever = true,
        .userAvailable = false
    },
};

/* Elements in kernel_device_frames may be enabled in specific configurations
 * only, but the ARRAY_SIZE() macro will automatically take care of this.
 * However, one corner case remains unsolved where all elements are disabled
 * and this becomes an empty array effectively. Then the C parser used in the
 * formal verification process will fail, because it follows the strict C rules
 * which do not allow empty arrays. Luckily, we have not met this case yet...
 */
#define NUM_KERNEL_DEVICE_FRAMES ARRAY_SIZE(kernel_device_frames)

/* PHYSICAL MEMORY */
static const p_region_t BOOT_RODATA avail_p_regs[] = {
    /* /memory@40000000 */
    {
        .start = 0x40000000,
        .end   = 0x80000000
    },
};

#endif /* !__ASSEMBLER__ */