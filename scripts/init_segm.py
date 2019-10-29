# IDAPython script
# author: weizi
#
# written in python3, tested on IDA Pro 7.4

"""
auto rename functions in .init_array segment to
init_{XXXXXXXX}
"""

import idc
import idaapi
import idautils

init_array_segm = idaapi.get_segm_by_name('.init_array')
segm_start_ea = init_array_segm.start_ea
segm_end_ea   = init_array_segm.end_ea
print(f"segm: start_ea={segm_start_ea:#x}, end_ea={segm_end_ea:#x}")

info = idaapi.get_inf_structure()
if info.is_64bit():
    size = 8
    get_ptr = idaapi.get_qword
else:
    size = 4
    get_ptr = idaapi.get_dword

for addr in range(segm_start_ea, segm_end_ea, size):
    func_addr = get_ptr(addr)
    idc.set_name(func_addr, f"init_{func_addr:X}")
