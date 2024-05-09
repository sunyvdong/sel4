/* Generated file. Your changes will be overwritten. */

#include <capdl.h>
#include <sel4/sel4.h>

#ifndef INVALID_SLOT
#define INVALID_SLOT (-1)
#endif

#define MAX_OBJECTS 139

CDL_Model capdl_spec = {
#if !defined(CONFIG_ARCH_ARM)
#    error "invalid target architecture; expecting ARM"
#endif
.num = 139,
.num_irqs = 1,
.irqs = (CDL_ObjID[]){
-1
},
.objects = (CDL_Object[]) {
[0] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "device_untyped",
#endif
.type = CDL_Untyped,
.size_bits = 12,
.paddr = 0xf8001000,
},
[1] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0000",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 65536,
.file_data_type = {.filename = "client",
.file_offset = 0
}},}
 },
},
[2] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0033",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[3] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0034",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[4] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0035",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[5] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0036",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[6] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0037",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[7] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0038",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[8] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0039",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[9] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0040",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[10] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0041",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[11] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0042",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[12] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0043",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[13] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0044",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[14] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0045",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[15] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0046",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[16] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0047",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[17] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0048",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[18] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0000",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 65536,
.file_data_type = {.filename = "timer",
.file_offset = 0
}},}
 },
},
[19] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0049",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[20] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0050",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[21] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0051",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[22] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0052",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[23] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0053",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[24] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0054",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[25] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0055",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[26] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0056",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[27] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0057",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[28] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0058",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[29] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0059",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[30] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0060",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[31] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0061",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[32] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0062",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[33] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0063",
#endif
.type = CDL_Frame,
.size_bits = 16,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[34] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "vspace_client",
#endif
.type = CDL_PD,
.slots.num = 2,
.slots.slot = (CDL_CapSlot[]) {
{0, {.type = CDL_PTCap, .obj_id = 129 /* pt_client_0000 */, .is_orig = true}},
{1, {.type = CDL_PTCap, .obj_id = 130 /* pt_client_0046 */, .is_orig = true}},

},
},
[35] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "vspace_timer",
#endif
.type = CDL_PD,
.slots.num = 2,
.slots.slot = (CDL_CapSlot[]) {
{0, {.type = CDL_PTCap, .obj_id = 131 /* pt_timer_0000 */, .is_orig = true}},
{1, {.type = CDL_PTCap, .obj_id = 132 /* pt_timer_0061 */, .is_orig = true}},

},
},
[36] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 122880
}},}
 },
},
[37] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0001",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 65536
}},}
 },
},
[38] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0002",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 69632
}},}
 },
},
[39] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0003",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 73728
}},}
 },
},
[40] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0004",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 77824
}},}
 },
},
[41] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0005",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 81920
}},}
 },
},
[42] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0006",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 86016
}},}
 },
},
[43] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0007",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 90112
}},}
 },
},
[44] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0008",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 94208
}},}
 },
},
[45] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0009",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 98304
}},}
 },
},
[46] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0010",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 102400
}},}
 },
},
[47] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0011",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 3544,
.file_data_type = {.filename = "client",
.file_offset = 106496
}},}
 },
},
[48] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0012",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 4068,
.dest_len = 28,
.file_data_type = {.filename = "client",
.file_offset = 110564
}},}
 },
},
[49] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0013",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 110592
}},}
 },
},
[50] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0031",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 20,
.file_data_type = {.filename = "client",
.file_offset = 184320
}},}
 },
},
[51] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0032",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[52] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0049",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[53] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0050",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[54] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0051",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[55] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0052",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[56] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_client_0053",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[57] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0001",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 65536
}},}
 },
},
[58] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0002",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 69632
}},}
 },
},
[59] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0003",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 73728
}},}
 },
},
[60] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0004",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 77824
}},}
 },
},
[61] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0005",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 81920
}},}
 },
},
[62] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0006",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 86016
}},}
 },
},
[63] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0007",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 90112
}},}
 },
},
[64] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0008",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 94208
}},}
 },
},
[65] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0009",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 98304
}},}
 },
},
[66] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0010",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 102400
}},}
 },
},
[67] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0011",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 106496
}},}
 },
},
[68] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0012",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 110592
}},}
 },
},
[69] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0013",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 3128,
.file_data_type = {.filename = "timer",
.file_offset = 114688
}},}
 },
},
[70] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0014",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 4068,
.dest_len = 28,
.file_data_type = {.filename = "timer",
.file_offset = 118756
}},}
 },
},
[71] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0015",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 118784
}},}
 },
},
[72] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0034",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 20,
.file_data_type = {.filename = "timer",
.file_offset = 196608
}},}
 },
},
[73] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0035",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[74] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0036",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[75] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0037",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[76] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0038",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[77] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0039",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[78] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0040",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[79] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0041",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[80] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0042",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[81] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0043",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[82] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0044",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[83] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0045",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[84] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0046",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[85] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0047",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[86] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0048",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[87] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0064",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[88] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0065",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[89] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0066",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[90] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0067",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[91] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0068",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[92] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0069",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[93] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0070",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[94] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "frame_timer_0071",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { }
 },
},
[95] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "ipc_client_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 180224
}},}
 },
},
[96] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "ipc_timer_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 192512
}},}
 },
},
[97] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_0_client_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 114688
}},}
 },
},
[98] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_0_timer_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 126976
}},}
 },
},
[99] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_10_client_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 155648
}},}
 },
},
[100] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_10_timer_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 167936
}},}
 },
},
[101] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_11_client_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 159744
}},}
 },
},
[102] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_11_timer_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 172032
}},}
 },
},
[103] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_12_client_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 163840
}},}
 },
},
[104] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_12_timer_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 176128
}},}
 },
},
[105] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_13_client_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 167936
}},}
 },
},
[106] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_13_timer_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 180224
}},}
 },
},
[107] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_14_client_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 172032
}},}
 },
},
[108] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_14_timer_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 184320
}},}
 },
},
[109] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_15_client_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 176128
}},}
 },
},
[110] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_15_timer_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 188416
}},}
 },
},
[111] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_1_client_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 118784
}},}
 },
},
[112] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_1_timer_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 131072
}},}
 },
},
[113] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_2_client_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 122880
}},}
 },
},
[114] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_2_timer_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 135168
}},}
 },
},
[115] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_3_client_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 126976
}},}
 },
},
[116] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_3_timer_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 139264
}},}
 },
},
[117] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_4_client_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 131072
}},}
 },
},
[118] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_4_timer_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 143360
}},}
 },
},
[119] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_5_client_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 135168
}},}
 },
},
[120] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_5_timer_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 147456
}},}
 },
},
[121] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_6_client_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 139264
}},}
 },
},
[122] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_6_timer_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 151552
}},}
 },
},
[123] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_7_client_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 143360
}},}
 },
},
[124] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_7_timer_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 155648
}},}
 },
},
[125] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_8_client_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 147456
}},}
 },
},
[126] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_8_timer_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 159744
}},}
 },
},
[127] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_9_client_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "client",
.file_offset = 151552
}},}
 },
},
[128] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "stack_9_timer_obj",
#endif
.type = CDL_Frame,
.size_bits = 12,
.frame_extra = { .paddr = 0,.fill = { {.type = CDL_FrameFill_FileData,
.dest_offset = 0,
.dest_len = 4096,
.file_data_type = {.filename = "timer",
.file_offset = 163840
}},}
 },
},
[129] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "pt_client_0000",
#endif
.type = CDL_PT,
.slots.num = 45,
.slots.slot = (CDL_CapSlot[]) {
{16, {.type = CDL_FrameCap, .obj_id = 1 /* frame_client_0000 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{32, {.type = CDL_FrameCap, .obj_id = 37 /* frame_client_0001 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{33, {.type = CDL_FrameCap, .obj_id = 38 /* frame_client_0002 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{34, {.type = CDL_FrameCap, .obj_id = 39 /* frame_client_0003 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{35, {.type = CDL_FrameCap, .obj_id = 40 /* frame_client_0004 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{36, {.type = CDL_FrameCap, .obj_id = 41 /* frame_client_0005 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{37, {.type = CDL_FrameCap, .obj_id = 42 /* frame_client_0006 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{38, {.type = CDL_FrameCap, .obj_id = 43 /* frame_client_0007 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{39, {.type = CDL_FrameCap, .obj_id = 44 /* frame_client_0008 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{40, {.type = CDL_FrameCap, .obj_id = 45 /* frame_client_0009 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{41, {.type = CDL_FrameCap, .obj_id = 46 /* frame_client_0010 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{42, {.type = CDL_FrameCap, .obj_id = 47 /* frame_client_0011 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{43, {.type = CDL_FrameCap, .obj_id = 48 /* frame_client_0012 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{44, {.type = CDL_FrameCap, .obj_id = 49 /* frame_client_0013 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{45, {.type = CDL_FrameCap, .obj_id = 97 /* stack_0_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{46, {.type = CDL_FrameCap, .obj_id = 111 /* stack_1_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{47, {.type = CDL_FrameCap, .obj_id = 113 /* stack_2_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{48, {.type = CDL_FrameCap, .obj_id = 115 /* stack_3_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{49, {.type = CDL_FrameCap, .obj_id = 117 /* stack_4_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{50, {.type = CDL_FrameCap, .obj_id = 119 /* stack_5_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{51, {.type = CDL_FrameCap, .obj_id = 121 /* stack_6_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{52, {.type = CDL_FrameCap, .obj_id = 123 /* stack_7_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{53, {.type = CDL_FrameCap, .obj_id = 125 /* stack_8_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{54, {.type = CDL_FrameCap, .obj_id = 127 /* stack_9_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{55, {.type = CDL_FrameCap, .obj_id = 99 /* stack_10_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{56, {.type = CDL_FrameCap, .obj_id = 101 /* stack_11_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{57, {.type = CDL_FrameCap, .obj_id = 103 /* stack_12_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{58, {.type = CDL_FrameCap, .obj_id = 105 /* stack_13_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{59, {.type = CDL_FrameCap, .obj_id = 107 /* stack_14_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{60, {.type = CDL_FrameCap, .obj_id = 109 /* stack_15_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{61, {.type = CDL_FrameCap, .obj_id = 95 /* ipc_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{62, {.type = CDL_FrameCap, .obj_id = 50 /* frame_client_0031 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{63, {.type = CDL_FrameCap, .obj_id = 51 /* frame_client_0032 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{64, {.type = CDL_FrameCap, .obj_id = 2 /* frame_client_0033 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{80, {.type = CDL_FrameCap, .obj_id = 3 /* frame_client_0034 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{96, {.type = CDL_FrameCap, .obj_id = 4 /* frame_client_0035 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{112, {.type = CDL_FrameCap, .obj_id = 5 /* frame_client_0036 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{128, {.type = CDL_FrameCap, .obj_id = 6 /* frame_client_0037 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{144, {.type = CDL_FrameCap, .obj_id = 7 /* frame_client_0038 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{160, {.type = CDL_FrameCap, .obj_id = 8 /* frame_client_0039 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{176, {.type = CDL_FrameCap, .obj_id = 9 /* frame_client_0040 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{192, {.type = CDL_FrameCap, .obj_id = 10 /* frame_client_0041 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{208, {.type = CDL_FrameCap, .obj_id = 11 /* frame_client_0042 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{224, {.type = CDL_FrameCap, .obj_id = 12 /* frame_client_0043 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{240, {.type = CDL_FrameCap, .obj_id = 13 /* frame_client_0044 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},

},
},
[130] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "pt_client_0046",
#endif
.type = CDL_PT,
.slots.num = 9,
.slots.slot = (CDL_CapSlot[]) {
{0, {.type = CDL_FrameCap, .obj_id = 14 /* frame_client_0045 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{16, {.type = CDL_FrameCap, .obj_id = 15 /* frame_client_0046 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{32, {.type = CDL_FrameCap, .obj_id = 16 /* frame_client_0047 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{48, {.type = CDL_FrameCap, .obj_id = 17 /* frame_client_0048 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{64, {.type = CDL_FrameCap, .obj_id = 52 /* frame_client_0049 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{65, {.type = CDL_FrameCap, .obj_id = 53 /* frame_client_0050 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{66, {.type = CDL_FrameCap, .obj_id = 54 /* frame_client_0051 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{67, {.type = CDL_FrameCap, .obj_id = 55 /* frame_client_0052 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{68, {.type = CDL_FrameCap, .obj_id = 56 /* frame_client_0053 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},

},
},
[131] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "pt_timer_0000",
#endif
.type = CDL_PT,
.slots.num = 60,
.slots.slot = (CDL_CapSlot[]) {
{16, {.type = CDL_FrameCap, .obj_id = 18 /* frame_timer_0000 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{32, {.type = CDL_FrameCap, .obj_id = 57 /* frame_timer_0001 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{33, {.type = CDL_FrameCap, .obj_id = 58 /* frame_timer_0002 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{34, {.type = CDL_FrameCap, .obj_id = 59 /* frame_timer_0003 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{35, {.type = CDL_FrameCap, .obj_id = 60 /* frame_timer_0004 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{36, {.type = CDL_FrameCap, .obj_id = 61 /* frame_timer_0005 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{37, {.type = CDL_FrameCap, .obj_id = 62 /* frame_timer_0006 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{38, {.type = CDL_FrameCap, .obj_id = 63 /* frame_timer_0007 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{39, {.type = CDL_FrameCap, .obj_id = 64 /* frame_timer_0008 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{40, {.type = CDL_FrameCap, .obj_id = 65 /* frame_timer_0009 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{41, {.type = CDL_FrameCap, .obj_id = 66 /* frame_timer_0010 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{42, {.type = CDL_FrameCap, .obj_id = 67 /* frame_timer_0011 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{43, {.type = CDL_FrameCap, .obj_id = 68 /* frame_timer_0012 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{44, {.type = CDL_FrameCap, .obj_id = 69 /* frame_timer_0013 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{45, {.type = CDL_FrameCap, .obj_id = 70 /* frame_timer_0014 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{46, {.type = CDL_FrameCap, .obj_id = 71 /* frame_timer_0015 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{47, {.type = CDL_FrameCap, .obj_id = 36 /* frame */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{48, {.type = CDL_FrameCap, .obj_id = 98 /* stack_0_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{49, {.type = CDL_FrameCap, .obj_id = 112 /* stack_1_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{50, {.type = CDL_FrameCap, .obj_id = 114 /* stack_2_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{51, {.type = CDL_FrameCap, .obj_id = 116 /* stack_3_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{52, {.type = CDL_FrameCap, .obj_id = 118 /* stack_4_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{53, {.type = CDL_FrameCap, .obj_id = 120 /* stack_5_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{54, {.type = CDL_FrameCap, .obj_id = 122 /* stack_6_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{55, {.type = CDL_FrameCap, .obj_id = 124 /* stack_7_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{56, {.type = CDL_FrameCap, .obj_id = 126 /* stack_8_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{57, {.type = CDL_FrameCap, .obj_id = 128 /* stack_9_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{58, {.type = CDL_FrameCap, .obj_id = 100 /* stack_10_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{59, {.type = CDL_FrameCap, .obj_id = 102 /* stack_11_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{60, {.type = CDL_FrameCap, .obj_id = 104 /* stack_12_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{61, {.type = CDL_FrameCap, .obj_id = 106 /* stack_13_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{62, {.type = CDL_FrameCap, .obj_id = 108 /* stack_14_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{63, {.type = CDL_FrameCap, .obj_id = 110 /* stack_15_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{64, {.type = CDL_FrameCap, .obj_id = 96 /* ipc_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{65, {.type = CDL_FrameCap, .obj_id = 72 /* frame_timer_0034 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{66, {.type = CDL_FrameCap, .obj_id = 73 /* frame_timer_0035 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{67, {.type = CDL_FrameCap, .obj_id = 74 /* frame_timer_0036 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{68, {.type = CDL_FrameCap, .obj_id = 75 /* frame_timer_0037 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{69, {.type = CDL_FrameCap, .obj_id = 76 /* frame_timer_0038 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{70, {.type = CDL_FrameCap, .obj_id = 77 /* frame_timer_0039 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{71, {.type = CDL_FrameCap, .obj_id = 78 /* frame_timer_0040 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{72, {.type = CDL_FrameCap, .obj_id = 79 /* frame_timer_0041 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{73, {.type = CDL_FrameCap, .obj_id = 80 /* frame_timer_0042 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{74, {.type = CDL_FrameCap, .obj_id = 81 /* frame_timer_0043 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{75, {.type = CDL_FrameCap, .obj_id = 82 /* frame_timer_0044 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{76, {.type = CDL_FrameCap, .obj_id = 83 /* frame_timer_0045 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{77, {.type = CDL_FrameCap, .obj_id = 84 /* frame_timer_0046 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{78, {.type = CDL_FrameCap, .obj_id = 85 /* frame_timer_0047 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{79, {.type = CDL_FrameCap, .obj_id = 86 /* frame_timer_0048 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{80, {.type = CDL_FrameCap, .obj_id = 19 /* frame_timer_0049 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{96, {.type = CDL_FrameCap, .obj_id = 20 /* frame_timer_0050 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{112, {.type = CDL_FrameCap, .obj_id = 21 /* frame_timer_0051 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{128, {.type = CDL_FrameCap, .obj_id = 22 /* frame_timer_0052 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{144, {.type = CDL_FrameCap, .obj_id = 23 /* frame_timer_0053 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{160, {.type = CDL_FrameCap, .obj_id = 24 /* frame_timer_0054 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{176, {.type = CDL_FrameCap, .obj_id = 25 /* frame_timer_0055 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{192, {.type = CDL_FrameCap, .obj_id = 26 /* frame_timer_0056 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{208, {.type = CDL_FrameCap, .obj_id = 27 /* frame_timer_0057 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{224, {.type = CDL_FrameCap, .obj_id = 28 /* frame_timer_0058 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{240, {.type = CDL_FrameCap, .obj_id = 29 /* frame_timer_0059 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},

},
},
[132] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "pt_timer_0061",
#endif
.type = CDL_PT,
.slots.num = 12,
.slots.slot = (CDL_CapSlot[]) {
{0, {.type = CDL_FrameCap, .obj_id = 30 /* frame_timer_0060 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{16, {.type = CDL_FrameCap, .obj_id = 31 /* frame_timer_0061 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{32, {.type = CDL_FrameCap, .obj_id = 32 /* frame_timer_0062 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{48, {.type = CDL_FrameCap, .obj_id = 33 /* frame_timer_0063 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{64, {.type = CDL_FrameCap, .obj_id = 87 /* frame_timer_0064 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{65, {.type = CDL_FrameCap, .obj_id = 88 /* frame_timer_0065 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{66, {.type = CDL_FrameCap, .obj_id = 89 /* frame_timer_0066 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{67, {.type = CDL_FrameCap, .obj_id = 90 /* frame_timer_0067 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{68, {.type = CDL_FrameCap, .obj_id = 91 /* frame_timer_0068 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{69, {.type = CDL_FrameCap, .obj_id = 92 /* frame_timer_0069 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{70, {.type = CDL_FrameCap, .obj_id = 93 /* frame_timer_0070 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{71, {.type = CDL_FrameCap, .obj_id = 94 /* frame_timer_0071 */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},

},
},
[133] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "tcb_client",
#endif
.type = CDL_TCB,
.tcb_extra = {
#if (0x3d000 & ((1 << seL4_IPCBufferSizeBits) - 1)) != 0
#    error "IPC buffer not correctly aligned"
#endif
.ipcbuffer_addr = 0x3d000,
.priority = 254,
.max_priority = 254,
.affinity = 0,
.pc = 0x10164,
.sp = 0x2e000,
.init = (const seL4_Word[]){0, 0, 0, 0, 2, 180232, 1, 0, 0, 32, 76472, 0, 0},
.init_sz = 13,
.domain = 0,
.resume = 1,
.fault_ep = 0,
},
.slots.num = 3,
.slots.slot = (CDL_CapSlot[]) {
{0, {.type = CDL_CNodeCap, .obj_id = 136 /* cnode_client */, .is_orig = true, .rights = CDL_AllRights, .data = CDL_CapData_MakeGuard(30, 0)}},
{1, {.type = CDL_PDCap, .obj_id = 34 /* vspace_client */, .is_orig = true}},
{4, {.type = CDL_FrameCap, .obj_id = 95 /* ipc_client_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},

},
},
[134] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "tcb_timer",
#endif
.type = CDL_TCB,
.tcb_extra = {
#if (0x40000 & ((1 << seL4_IPCBufferSizeBits) - 1)) != 0
#    error "IPC buffer not correctly aligned"
#endif
.ipcbuffer_addr = 0x40000,
.priority = 254,
.max_priority = 254,
.affinity = 0,
.pc = 0x10164,
.sp = 0x31000,
.init = (const seL4_Word[]){0, 0, 0, 0, 2, 188456, 1, 0, 0, 32, 83424, 0, 0},
.init_sz = 13,
.domain = 0,
.resume = 1,
.fault_ep = 0,
},
.slots.num = 3,
.slots.slot = (CDL_CapSlot[]) {
{0, {.type = CDL_CNodeCap, .obj_id = 135 /* cnode_timer */, .is_orig = true, .rights = CDL_AllRights, .data = CDL_CapData_MakeGuard(28, 0)}},
{1, {.type = CDL_PDCap, .obj_id = 35 /* vspace_timer */, .is_orig = true}},
{4, {.type = CDL_FrameCap, .obj_id = 96 /* ipc_timer_obj */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},

},
},
[135] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "cnode_timer",
#endif
.type = CDL_CNode,
.size_bits = 4,
.slots.num = 8,
.slots.slot = (CDL_CapSlot[]) {
{1, {.type = CDL_EPCap, .obj_id = 137 /* endpoint */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite|CDL_CanGrant), .data = { .tag = CDL_CapData_Badge, .badge = 0}}},
{2, {.type = CDL_NotificationCap, .obj_id = 138 /* ntfn */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite|CDL_CanGrant), .data = { .tag = CDL_CapData_Badge, .badge = 0}}},
{3, {.type = CDL_UntypedCap, .obj_id = 0 /* device_untyped */}},
{5, {.type = CDL_CNodeCap, .obj_id = 135 /* cnode_timer */, .is_orig = true, .rights = CDL_AllRights, .data = CDL_CapData_MakeGuard(28, 0)}},
{6, {.type = CDL_PDCap, .obj_id = 35 /* vspace_timer */, .is_orig = true}},
{7, {.type = CDL_FrameCap, .obj_id = 36 /* frame */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite|CDL_CanGrant), .vm_attribs = seL4_ARCH_Default_VMAttributes, .mapping_container_id = INVALID_OBJ_ID, .mapping_slot = 0}},
{8, {.type = CDL_IRQControlCap}},
{10, {.type = CDL_TCBCap, .obj_id = 134 /* tcb_timer */, .is_orig = true, .rights = CDL_AllRights}},

},
},
[136] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "cnode_client",
#endif
.type = CDL_CNode,
.size_bits = 2,
.slots.num = 2,
.slots.slot = (CDL_CapSlot[]) {
{1, {.type = CDL_EPCap, .obj_id = 137 /* endpoint */, .is_orig = true, .rights = (CDL_CanRead|CDL_CanWrite|CDL_CanGrant), .data = { .tag = CDL_CapData_Badge, .badge = 61}}},
{2, {.type = CDL_TCBCap, .obj_id = 133 /* tcb_client */, .is_orig = true, .rights = CDL_AllRights}},

},
},
[137] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "endpoint",
#endif
.type = CDL_Endpoint,
},
[138] = {
#ifdef CONFIG_DEBUG_BUILD
.name = "ntfn",
#endif
.type = CDL_Notification,
},

},
.num_untyped = 0,
.untyped = NULL,
.num_asid_slots = 1,
.asid_slots = (CDL_ObjID[]){
    (CDL_ObjID)-1 /* slot reserved for root thread, ignored */
},
};