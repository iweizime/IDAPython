# IDAPython script
# author: weizi
#
# written in python3, tested on IDA Pro 7.4


"""
this script finds all std::string constructors then rename them to
string_{XXXXXXXX}, and set the first argument type to std::string

you may need to change the key string and key func
"""


import idc
import idaapi
import idautils

from itertools import chain


def find_key_str(target):
    for string in idautils.Strings():
        if target == str(string):
            return string.ea
    return None

def find_key_func(target):
    return idc.get_name_ea_simple(target)


def collect_all_possible_funcs(key_str_ea, key_func_ea):
    all_funcs = []
    for ref in chain(idautils.XrefsTo(key_str_ea),idautils.XrefsTo(key_func_ea)):
        func = idaapi.get_func(ref.frm)
        if func not in all_funcs:
            all_funcs.append(func)

    return all_funcs

def filter_func(all_possible_funcs, max_call_cnt = 4, only_sub=False):
    class func_calls_t(idaapi.ctree_visitor_t):
        def __init__(self):
            idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
            self.call_cnt = 0

        def visit_expr(self, e):
            if e.op == idaapi.cot_call:
                self.call_cnt += 1
            return 0

    all_funcs = []
    for func in all_possible_funcs:
        if only_sub:
            func_name = idaapi.get_name(func.start_ea)
            if not func_name.startswith('sub'):
                continue
        cfunc = idaapi.decompile(func)
        visitor = func_calls_t()
        visitor.apply_to(cfunc.body, None)
        if visitor.call_cnt <= max_call_cnt:
            all_funcs.append(func)
    return all_funcs

def process_funcs(all_funcs):
    for func in all_funcs:
        # rename
        idc.set_name(func.start_ea, f"string_{func.start_ea:X}")

        # set type
        struc_id = idaapi.get_struc_id("std::string")
        # print(f"{struc_id:x}")

        if struc_id == idaapi.BADADDR:
            idc.set_local_type(-1, "struct std::string {char *ptr; size_t length; char buf[0x10];};", idaapi.PT_TYP)
            print("create std::string")

        func_tinfo = idaapi.tinfo_t()
        cfunc = idaapi.decompile(func.start_ea)
        cfunc.get_func_type(func_tinfo)
        func_details = idaapi.func_type_data_t()
        func_tinfo.get_func_details(func_details)


        std_string_tinfo = idaapi.tinfo_t()
        std_string_tinfo.get_named_type(idaapi.get_idati(), "std::string")
        std_string_ptr_tinfo = idaapi.tinfo_t()
        std_string_ptr_tinfo.create_ptr(std_string_tinfo)

        func_details[0].type = std_string_ptr_tinfo
        func_tinfo.create_func(func_details)
        idaapi.apply_tinfo(func.start_ea, func_tinfo, idaapi.TINFO_DEFINITE)



def main():
    key_str_ea = find_key_str("basic_string::_M_construct null not valid")
    key_func_ea = find_key_func("._ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERmm")
    all_possible_funcs = collect_all_possible_funcs(key_str_ea, key_func_ea)
    print("all possible funcs")
    for func in all_possible_funcs:
        print(idaapi.get_name(func.start_ea))

    print("all funcs")
    all_funcs = filter_func(all_possible_funcs, 4, False)
    for func in all_funcs:
        print(idaapi.get_name(func.start_ea))
    process_funcs(all_funcs)
main()

