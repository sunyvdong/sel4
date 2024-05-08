/*
 * Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#pragma once

#define HARDWARE_TIMER_INTERFACES                                                   \
    consumes Dummy gpt1;                                                           \
    consumes Dummy gpt2;                                                             \
    emits Dummy dummy_source;
#define HARDWARE_TIMER_ATTRIBUTES
#define HARDWARE_TIMER_COMPOSITION                                                  \
        connection seL4DTBHardware gpt_conn1(from dummy_source, to gpt1);         \
        connection seL4DTBHardware gpt_conn2(from dummy_source, to gpt2);
#define HARDWARE_TIMER_CONFIG                                                                       \
        gpt1.dtb = dtb({"path" : "/gpt@302d0000"});                           \
        gpt1.generate_interrupts = 1;                                                              \
        gpt2.dtb = dtb({"path" : "/gpt@302e0000"});                              \
        gpt2.generate_interrupts = 1;
#define HARDWARE_TIMER_PLAT_INTERFACES
