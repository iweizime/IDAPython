# IDAPython script
# author: weizi
#
# written in python3, tested on IDA Pro 7.4


"""
this script creates struct with given name and size. The fields of structs
are QWORD or DWORD acorrding cpu architecture.
"""

import idc
import idaapi
import idautils

def add_struct(name, size):
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        step_size = 8
        flag = idaapi.FF_DATA | idaapi.FF_QWORD
    else:
        step_size = 4
        flag = idaapi.FF_DATA | idaapi.FF_DWORD

    id = idaapi.add_struc(idaapi.BADADDR, name)
    if id == idaapi.BADADDR:
        id = idaapi.get_struc_id(name)
    struc = idaapi.get_struc(id)
    for off in range(0, size, step_size):
        idaapi.add_struc_member(struc, f"field_{off:X}", off, flag, None, step_size)

add_struct("SocketServer", 0xb80)
