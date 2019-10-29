# IDAPython script
# author: weizi
#
# written in python3, tested on IDA Pro 7.4


"""
this script can modify the printk function's arguments to show
the real strings by removing log_level prefix
"""

import idc
import idautils
import idaapi

class func_args_modifier_t(idaapi.ctree_visitor_t):
    def __init__(self, ea):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.ea = ea

    def visit_expr(self, e):
        if e.op == idaapi.cot_call and \
            e.x.op == idaapi.cot_obj and \
            e.x.obj_ea == self.ea:
                arg = e.a[0]
                # print(f"arg={arg}, arg.op={arg.op}")
                t = idaapi.tinfo_t.get_stock(idaapi.STI_PCHAR)
                if arg.op == idaapi.cot_obj:
                    prefix = idaapi.get_bytes(arg.obj_ea, 2)
                    # print(prefix)
                    if prefix[0] == 1:
                        log_level = chr(prefix[1])
                        idaapi.del_items(arg.obj_ea)
                        arg.obj_ea += 2
                    idc.create_strlit(arg.obj_ea, idaapi.BADADDR)
                    arg.type = t
                    arg.exflags = idaapi.EXFL_CSTR
        return 0

class printk_hooks_t(idaapi.Hexrays_Hooks):
    def __init__(self):
        idaapi.Hexrays_Hooks.__init__(self)
        self.modifier = func_args_modifier_t(idc.get_name_ea_simple('printk'))

    def maturity(self, cfunc, maturity):
        if maturity == idaapi.CMAT_FINAL:
            self.modifier.apply_to(cfunc.body, None)

hook = printk_hooks_t()
hook.hook()
