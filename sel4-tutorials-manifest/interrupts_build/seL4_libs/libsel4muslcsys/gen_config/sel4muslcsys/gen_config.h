#pragma once

#define CONFIG_LIB_SEL4_MUSLC_SYS_MORECORE_BYTES  1048576
/* disabled: CONFIG_LIB_SEL4_MUSLC_SYS_DEBUG_HALT */
/* disabled: CONFIG_LIB_SEL4_MUSLC_SYS_CPIO_FS */
/* disabled: CONFIG_LIB_SEL4_MUSLC_SYS_ARCH_PUTCHAR_WEAK */
#define CONFIG_LIB_SEL4_MUSLC_SYS_CONSTRUCTOR_PRIORITY  MUSLCSYS_WITH_VSYSCALL_PRIORITY + 10
