import idaapi
import idautils
import ida_kernwin
import ida_xref
import ida_bytes
import ida_nalt
import ida_name
import idc
import ida_hexrays
import ida_lines
from pprint import pprint

binded_hotkeys = []


def cleanup():
    remove_all_hotkey()


def add_hotkey(hotkey, func):
    binded_hotkeys.append(ida_kernwin.add_hotkey(hotkey, func))


def remove_all_hotkey():
    global binded_hotkeys
    for hotkey in binded_hotkeys:
        ida_kernwin.del_hotkey(hotkey)
    binded_hotkeys = []


def fixup_field_names():
    current_address = ida_kernwin.get_screen_ea()
    for i in range(10000000000):
        string_field_const_char_ptr = ida_xref.get_first_dref_from(current_address)
        print(hex(string_field_const_char_ptr))
        if string_field_const_char_ptr != idaapi.BADADDR:
            string_field_strlit = ida_bytes.get_strlit_contents(
                string_field_const_char_ptr, -1, ida_nalt.STRTYPE_TERMCHR
            )
            if string_field_strlit is not None and len(string_field_strlit) > 0:
                string_field = string_field_strlit.decode("ascii")
                print(string_field)

                int_index_address = current_address + 8
                ida_name.set_name(int_index_address, "_" + string_field + "_")

            current_address += 16
        else:
            print(
                "Couldn't fix up field names at address "
                + "0x{:X}".format(current_address)
                + " (most likely end of the array, jump to it and continue there until the next array block)"
            )
            break


def get_gml_function_names():
    for func_ea in idautils.Functions():
        # Get the function end address
        func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)

        # Iterate through instructions within the function
        ea = func_ea
        while ea < func_end:
            # Decode the instruction at the current address
            insn = idaapi.insn_t()
            if idaapi.decode_insn(insn, ea):
                mnem = idaapi.print_insn_mnem(ea)

                # Special case for 'LEA' instruction
                if mnem == "lea":
                    # Get the first operand, which is usually the effective address
                    op = insn.ops[
                        1
                    ]  # Typically LEA has the address in the second operand

                    if (
                        op.type == idaapi.o_mem or op.type == idaapi.o_displ
                    ):  # Memory or displacement type
                        pointed_addr = idc.get_operand_value(
                            ea, 1
                        )  # Get the address it points to
                        # Try to retrieve a string from the pointed address
                        pointed_str = idc.get_strlit_contents(pointed_addr)
                        if pointed_str:
                            pointed_str_utf8 = pointed_str.decode("utf-8")
                            if pointed_str_utf8 and (
                                pointed_str_utf8.startswith("gml_Script_")
                                or pointed_str_utf8.startswith("gml_Object_")
                            ):
                                # print(f"Function {pointed_str_utf8} at: {hex(func_ea)}")
                                idaapi.set_name(
                                    func_ea, pointed_str_utf8, idaapi.SN_FORCE
                                )
                                # return

                # Move to the next instruction
                ea = idc.next_head(ea)
            else:
                # If the instruction can't be decoded, break the loop
                break


def get_expr_block(cfunc, expr):
    """
    Given a cfunc_t object and a cexpr_t, find the block containing this expression.
    """
    # Start by finding the parent instruction
    parent_insn = cfunc.body.find_parent_of(expr)

    # Traverse upwards until we reach a block (cblock_t) or the top level of the function
    while parent_insn:
        if parent_insn.op == idaapi.cit_block:  # Check if it's a block
            del parent_insn
            return None
            # return parent_insn.cblock

        # Move up to the next parent
        parent_insn = cfunc.body.find_parent_of(parent_insn)

    return None  # No block found


def create_dummy_hexrays_const(value):
    num = ida_hexrays.cexpr_t()
    num.op = ida_hexrays.cot_num
    num.n = ida_hexrays.cnumber_t()
    num.n._value = value
    return num


def create_dummy_hexrays_insn():
    res = ida_hexrays.cinsn_t()
    res.op = ida_hexrays.cit_empty
    return res


def make_helper_insn(ea, name):
    return make_cexpr_insn(ea, make_helper_expr(name))


def make_cexpr_insn(ea, obj):
    insn = ida_hexrays.cinsn_t()
    insn.ea = ea
    insn.op = ida_hexrays.cit_expr
    insn.cexpr = obj
    insn.thisown = False
    return insn


def make_helper_expr(name, typ=False):
    obj = ida_hexrays.cexpr_t()
    obj.op = ida_hexrays.cot_helper
    obj.exflags |= ida_hexrays.EXFL_ALONE
    obj.helper = name
    if typ is not False:
        obj.type = typ
    return obj


class CleanupVisitor(ida_hexrays.ctree_parentee_t):
    """A visitor that cleans up the ctree by removing cit_empty items."""

    def clean_up(self, tree, parent):  # type: (...) -> None
        ida_hexrays.ctree_parentee_t.apply_to(self, tree, parent)

    def visit_insn(self, insn):  # type: (...) -> int
        if insn.op == ida_hexrays.cit_block:
            # This is pretty inefficient, but unfortunately we cannot traverse the list
            # and call erase() at the same time.
            # Manually traversing the list with begin(), end() and next() is bugged and throws
            # us in an infinite loop.
            # Trying to mutate the list while iterating over it is a sure way to cause crashes.

            to_delete = []

            for ins in insn.cblock:
                if ins.op == ida_hexrays.cit_empty:
                    to_delete.append(ins)

            for ins in to_delete:
                insn.cblock.remove(ins)

        return 0


def print_swig_object_vars(obj):
    # List all attributes and methods accessible via Python
    attributes = dir(obj)
    print("Attributes and methods of the SWIG object:")
    for attr in attributes:
        try:
            value = getattr(obj, attr)
            print(f"{attr} = {value}")
        except Exception as e:
            print(f"{attr} = <unreadable attribute: {e}>")


class DebugVisitor(ida_hexrays.ctree_parentee_t):
    """A visitor that just prints information about the ctree."""

    def visit(self, tree, parent):  # type: (...) -> None
        ida_hexrays.ctree_parentee_t.apply_to(self, tree, parent)

    def visit_insn(self, c):  # type: (...) -> int
        print("DEBUG: insn 0x%016lx: %s" % (c.ea, c.opname))
        return 0

    def visit_expr(self, c):  # type: (...) -> int
        print(
            "DEBUG: expr 0x%016lx: %s - type: %s %s"
            % (
                c.ea,
                c.opname,
                str(c.type),
                idaapi.get_name(c.obj_ea) if c.opname == "obj" else "",
            )
        )
        if c.op == ida_hexrays.cot_call:
            print("  a.functype: %s" % (str(c.a.functype)))
            print(
                "  x.ea: 0x%016lx - x.type: %s - x.op: %s"
                % (c.x.ea, str(c.x.type), c.x.opname)
            )
            for i, a in enumerate(c.a):
                print(
                    "  arg[%d]: ea: 0x%016lx - type: %s - op: %s %s"
                    % (
                        i,
                        a.ea,
                        str(a.type),
                        a.opname,
                        idaapi.get_name(a.obj_ea) if a.opname == "obj" else "",
                    )
                )
        return 0


def get_tinfo(name) -> idaapi.tinfo_t:
    tif = idaapi.tinfo_t()
    assert tif.get_named_type(idaapi.get_idati(), name)
    return tif.copy()


def get_ptr_tinfo(name) -> idaapi.tinfo_t:
    res = idaapi.tinfo_t()
    res.create_ptr(get_tinfo(name))
    return res


def get_array_tinfo(name, size) -> idaapi.tinfo_t:
    res = idaapi.tinfo_t()
    res.create_array(get_tinfo(name), 0, size)
    return res


def get_ptr_array_tinfo(name, size) -> idaapi.tinfo_t:
    res = idaapi.tinfo_t()
    res.create_array(get_ptr_tinfo(name), 0, size)
    return res


def set_lvar_type(src, t, vu, is_ptr=False):
    if isinstance(t, str):
        tif = idaapi.tinfo_t()
        if not tif.get_named_type(idaapi.get_idati(), t):
            print("couldn't convert {} into tinfo_t".format(t))
            return False
        if tif:
            if is_ptr:
                tif2 = idaapi.tinfo_t()
                tif2.create_ptr(tif)
                tif = tif2

            t = tif
        else:
            print("couldn't convert {} into tinfo_t".format(t))
            return False

    if not vu:
        return False
    lvars = [n for n in vu.cfunc.lvars if n.name == src]
    if len(lvars) == 1:
        print("changing type of {} to {}".format(lvars[0].name, t))
        return vu.set_lvar_type(lvars[0], t)
        # return True
    else:
        print("couldn't find var {}".format(src))
    return False


def ast_x_until_cot_var_or_cot_num(i):
    if i.op is idaapi.cot_var:
        return i.v.getv().name

    if i.op is idaapi.cot_num:
        return i.n._value

    if not i.x:
        return i

    return ast_x_until_cot_var_or_cot_num(i.x)


def remove_underscores(s):
    if s.startswith("_"):
        s = s[1:]

    if s.endswith("_"):
        s = s[:-1]

    return s


class CToGMLVisitor(ida_hexrays.ctree_visitor_t):
    """A visitor that makes the hexray pseudo c decompilation output more like the original GML."""

    def __init__(self, cfunc, vu):
        # lvars = cfunc.get_lvars()
        # print_swig_object_vars(cfunc.body.cblock)

        # ptr_tinfo = idaapi.tinfo_t()
        # print_swig_object_vars(ptr_tinfo)

        # for i in lvars:
        # print(i.type)
        # if str(i.type()).startswith("__m1"):
        # if i.type().is_array():
        # print(get_ptr_array_tinfo("RValue", i.type().get_array_nelems()))
        # i.set_lvar_type(
        # get_ptr_array_tinfo("RValue", i.type().get_array_nelems())
        # )
        # else:
        # i.set_lvar_type(get_tinfo("RValue"))
        # if self.detect_and_change_type_to_rvalue(i):
        # self.modified = True

        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_INSNS)

        self.cfunc = cfunc
        self.vu = vu
        self.modified = False
        self.instructions = []
        self.removed_debug_prolog = False
        # self.only_once = True

        # print_swig_object_vars(cfunc)
        # lvars = cfunc.get_lvars()
        # print_swig_object_vars(cfunc.body.cblock)
        # for i in cfunc.body.cblock:
        # if self.detect_and_change_type_to_rvalue(i):
        # self.modified = True
        # for l in lvars:
        # print(l.type())

    def do_passes(self):
        self.apply_to(self.vu.cfunc.body, None)

        self.second_pass()

    def second_pass(self):
        """At this point all instructions are inside self.instructions"""
        self.detect_and_rename_debug_context_line_number()

        self.simplify_call_method()

        self.simplify_array_get()

    def visit_insn(self, i):
        # First instruction cannot be modified. Don't store it so it's not possible to mess with it.
        if i.index != 0:
            self.instructions.append(i)

        if self.remove_noisy_function_calls(i):
            return 0

        if self.remove_free_rvalue_if_branches(i):
            return 0

        if self.simplify_rvalue_set_from_function(i):
            return 0

        if self.simplify_variable_set_value_direct(i):
            return 0

        if self.remove_if_checks_related_to_arg_count(i):
            return 0

        if self.remove_debug_epilog(i):
            return 0

        if self.detect_and_change_type_to_rvalue(i):
            return 0

        return 0

    def detect_and_change_type_to_rvalue(self, i):
        changed = False

        # if (
        #     i.op is idaapi.cit_expr
        #     and i.cexpr.op is idaapi.cot_asg
        #     and i.cexpr.x.op is idaapi.cot_ptr
        #     and i.cexpr.x.x.op is idaapi.cot_cast
        #     and i.cexpr.x.x.x.op is idaapi.cot_add
        #     and i.cexpr.x.x.x.x.op is idaapi.cot_var
        #     and i.cexpr.x.x.x.y.op is idaapi.cot_num
        #     and i.cexpr.y.op is idaapi.cot_num
        #     and i.cexpr.x.x.x.y.n._value == 12
        # ):
        if (
            i.op is idaapi.cit_expr
            and i.cexpr.op is idaapi.cot_asg
            and i.cexpr.x.op is idaapi.cot_var
            and i.cexpr.y.op is idaapi.cot_call
            and i.cexpr.y.x.op is idaapi.cot_ptr
            and i.cexpr.y.x.x.op is idaapi.cot_cast
            and i.cexpr.y.x.x.x.op is idaapi.cot_add
            and i.cexpr.y.x.x.x.x.op is idaapi.cot_ptr
            and i.cexpr.y.x.x.x.x.x.op is idaapi.cot_cast
            and i.cexpr.y.x.x.x.x.x.x.op is idaapi.cot_ref
            and i.cexpr.y.x.x.x.x.x.x.x.op is idaapi.cot_memptr
            and i.cexpr.y.x.x.x.x.x.x.x.x.op is idaapi.cot_var
            and i.cexpr.y.x.x.x.y.op is idaapi.cot_num
            and i.cexpr.y.a[0].op is idaapi.cot_var
            and i.cexpr.y.a[1].op is idaapi.cot_cast
            and i.cexpr.y.a[1].x.op is idaapi.cot_obj
        ):
            # if not self.only_once:
            # return False

            # self.only_once = False

            # print(i.cexpr.x.x.x.x.v.getv().type())
            # set_lvar_type(i.cexpr.x.x.x.x.v.getv().name, "RValue", self.vu, True)
            # print(i.cexpr.x.v.getv().name)

            # CRASHES FOR NO REASON, FUCK HEXRAY!
            # set_lvar_type(i.cexpr.x.v.getv().name, "RValue", self.vu, True)

            changed = True

        return changed

    def detect_and_rename_debug_context_line_number(self):
        var_ref = None
        cache_last_values = {}

        for i in self.instructions:
            if (
                i.op is idaapi.cit_expr
                and i.cexpr.op is idaapi.cot_asg
                and i.cexpr.x.op is idaapi.cot_var
                and i.cexpr.y.op is idaapi.cot_num
                and i.cexpr.x.v
            ):
                if i.cexpr.x.v.getv().name not in cache_last_values:
                    cache_last_values[i.cexpr.x.v.getv().name] = -1
                if i.cexpr.y.n._value > cache_last_values[i.cexpr.x.v.getv().name]:
                    cache_last_values[i.cexpr.x.v.getv().name] = i.cexpr.y.n._value
                    var_ref = i.cexpr.x
                else:
                    var_ref = None
                    break

        if var_ref is not None:
            # print_swig_object_vars(var_ref.v.getv())
            self.vu.rename_lvar(var_ref.v.getv(), "gml_debug_context_line_number", 1)
            self.modified = True

    def simplify_call_method(self):
        current_index = 0

        def find_the_array_get_call_and_do_simplify(old_i, instance_name, method_args):
            method_name = None
            for k_index in range(current_index - 1, current_index - 10, -1):
                k = self.instructions[k_index]
                if (
                    k.op is idaapi.cit_expr
                    and k.cexpr.op is idaapi.cot_call
                    and k.cexpr.x.op is idaapi.cot_obj
                    and "ARRAY_Get" in idaapi.get_name(k.cexpr.x.obj_ea)
                ):
                    method_name = remove_underscores(
                        idaapi.get_name(k.cexpr.a[1].obj_ea)
                    )
                    # print(idaapi.get_name(k.cexpr.a[1].obj_ea))
                    self.remove_instruction(k)

            if method_name is None:
                return

            old_i.cexpr.replace_by(
                make_helper_expr(f"{instance_name}.{method_name}({method_args})")
            )
            self.modified = True

        for i in self.instructions:
            # if i.cexpr and i.cexpr.x:
            # print(idaapi.get_name(i.cexpr.x.obj_ea) + " + " + hex(i.ea))
            if (
                # Call_Method(v287, a2, &v289, 0, &v644, 0i64);
                i.cexpr
                and i.cexpr.x
                and idaapi.get_name(i.cexpr.x.obj_ea) == "Call_Method"
            ):
                find_the_array_get_call_and_do_simplify(
                    i.cexpr,
                    ast_x_until_cot_var_or_cot_num(i.cexpr.a[0]),
                    ast_x_until_cot_var_or_cot_num(i.cexpr.a[5]),
                )
            elif (
                # v286 = Call_Method(v285, a2, &v290, 2, &v645, &v885.flags);
                i.op is idaapi.cit_expr
                and i.cexpr.op is idaapi.cot_asg
                and i.cexpr.x.op is idaapi.cot_var
                and i.cexpr.y.op is idaapi.cot_call
                and i.cexpr.y.x.op is idaapi.cot_obj
                and idaapi.get_name(i.cexpr.y.x.obj_ea) == "Call_Method"
            ):
                # print_swig_object_vars(i.cexpr.y.a[0])
                find_the_array_get_call_and_do_simplify(
                    i.cexpr,
                    ast_x_until_cot_var_or_cot_num(i.cexpr.y.a[0]),
                    ast_x_until_cot_var_or_cot_num(i.cexpr.y.a[5]),
                )

            current_index += 1

    def simplify_array_get(self):
        for i in self.instructions:
            if (
                # ARRAY_Get(self, undefined_, 0x80000000, &v18);
                i.cexpr
                and i.cexpr.x
                and "ARRAY_Get" in idaapi.get_name(i.cexpr.x.obj_ea)
            ):
                field_name = remove_underscores(idaapi.get_name(i.cexpr.a[1].obj_ea))
                i.cexpr.replace_by(
                    make_helper_expr(
                        f"{ast_x_until_cot_var_or_cot_num(i.cexpr.a[3])} = {ast_x_until_cot_var_or_cot_num(i.cexpr.a[0])}.{field_name}"
                    )
                )

    def simplify_variable_set_value_direct(self, i):
        changed = False

        if (
            i.op is idaapi.cit_expr
            and i.cexpr.op is idaapi.cot_call
            and i.cexpr.x.op is idaapi.cot_obj
            and idaapi.get_name(i.cexpr.x.obj_ea) == "Variable_SetValue_Direct"
        ):
            field_name = remove_underscores(idaapi.get_name(i.cexpr.a[1].obj_ea))
            i.cexpr.replace_by(
                make_helper_expr(
                    f"{i.cexpr.a[0].v.getv().name}.{field_name} = {ast_x_until_cot_var_or_cot_num(i.cexpr.a[3])}"
                )
            )

            changed = True

        return changed

    def simplify_rvalue_set_from_function(self, i):
        changed = False

        if (
            i.op is idaapi.cit_expr
            and i.cexpr.op is idaapi.cot_asg
            and i.cexpr.x.op is idaapi.cot_var
            and i.cexpr.y.op is idaapi.cot_call
            and i.cexpr.y.x.op is idaapi.cot_obj
            and idaapi.get_name(i.cexpr.y.x.obj_ea) == "RValue_Set_From_Function"
        ):
            func_name = remove_underscores(idaapi.get_name(i.cexpr.y.a[4].obj_ea))
            i.cexpr.replace_by(
                make_helper_expr(
                    f"{ast_x_until_cot_var_or_cot_num(i.cexpr.x)} = {func_name}({ast_x_until_cot_var_or_cot_num(i.cexpr.y.a[5])})"
                )
            )

        return changed

    def rename_gml_function_if_needed(self, i):
        if idaapi.get_name(self.cfunc.entry_ea).startswith("sub_") and (
            i.op is idaapi.cit_expr
            and i.cexpr.op is idaapi.cot_asg
            and i.cexpr.x.op is idaapi.cot_idx
            and i.cexpr.x.x.op is idaapi.cot_var
            and i.cexpr.x.y.op is idaapi.cot_num
            and i.cexpr.y.op is idaapi.cot_cast
            and i.cexpr.y.x.op is idaapi.cot_obj
        ):
            pointed_str = idc.get_strlit_contents(i.cexpr.y.x.obj_ea)
            if pointed_str:
                pointed_str_utf8 = pointed_str.decode("utf-8")
                if pointed_str_utf8 and (
                    pointed_str_utf8.startswith("gml_Script_")
                    or pointed_str_utf8.startswith("gml_Object_")
                ):
                    idaapi.set_name(
                        self.cfunc.entry_ea,
                        pointed_str_utf8,
                        idaapi.SN_FORCE,
                    )

    def remove_debug_prolog(self):
        if self.removed_debug_prolog:
            return False

        for i in self.instructions:
            self.rename_gml_function_if_needed(i)

            self.remove_instruction(i)
        self.removed_debug_prolog = True

        return True

    def remove_debug_epilog(self, i):
        changed = False

        if (
            i.op is idaapi.cit_expr
            and i.cexpr.op is idaapi.cot_asg
            and i.cexpr.x.op is idaapi.cot_ptr
            and i.cexpr.x.x.op is idaapi.cot_cast
            and i.cexpr.x.x.x.op is idaapi.cot_obj
            and i.cexpr.y.op is idaapi.cot_idx
            and i.cexpr.y.x.op is idaapi.cot_var
            and i.cexpr.y.y.op is idaapi.cot_num
            and idaapi.get_name(i.cexpr.x.x.x.obj_ea) == "SYYStackTrace::s_pStart"
        ):
            self.remove_instruction(i)
            changed = True

        if (
            i.op is idaapi.cit_expr
            and i.cexpr.op is idaapi.cot_asg
            and i.cexpr.x.op is idaapi.cot_obj
            and (i.cexpr.y.op is idaapi.cot_var or i.cexpr.y.op is idaapi.cot_num)
            and idaapi.get_name(i.cexpr.x.obj_ea) == "g_CurrentArrayOwner"
        ):
            self.remove_instruction(i)
            changed = True

        if (
            i.op is idaapi.cit_expr
            and i.cexpr.op is idaapi.cot_asg
            and i.cexpr.x.op is idaapi.cot_obj
            and i.cexpr.y.op is idaapi.cot_cast
            and i.cexpr.y.x.op is idaapi.cot_var
            and idaapi.get_name(i.cexpr.x.obj_ea) == "g_CurrentArrayOwner"
        ):
            self.remove_debug_prolog()
            changed = True

        return changed

    def remove_if_checks_related_to_arg_count(self, i):
        changed = False

        # if ( arg_count <= 2 )
        #     some_local_var = &rvalue_array;
        #   else
        #     some_local_var = *(args + 2);
        try:
            if i.op == ida_hexrays.cit_if:
                if_stmt = i.cif
                then_branch = if_stmt.ithen
                else_branch = if_stmt.ielse

                if (
                    then_branch
                    and else_branch
                    and idaapi.get_name(then_branch.cblock[0].cexpr.y.x.obj_ea)
                    == "rvalue_array"
                ):
                    # print_swig_object_vars(then_branch.cblock[0].cexpr.y.x)
                    # print(idaapi.get_name(then_branch.cblock[0].cexpr.y.x.obj_ea))
                    i.replace_by(if_stmt.ielse)
                    changed = True
        except Exception as _:
            pass

        # if ( arg_count <= 2 )
        #     some_local_var = *args
        try:
            if i.op == ida_hexrays.cit_if:
                if_stmt = i.cif
                then_branch = if_stmt.ithen
                if (
                    then_branch
                    and then_branch.cblock[0].cexpr.y.x.v.getv()
                    == self.cfunc.arguments[4]
                ):
                    i.replace_by(if_stmt.ithen)
                    changed = True
        except Exception as _:
            pass

        # some_local_var = &rvalue_array;
        try:
            if (
                i.op is idaapi.cit_expr
                and i.cexpr.op is idaapi.cot_asg
                and i.cexpr.x.op is idaapi.cot_var
                and i.cexpr.y.op is idaapi.cot_ref
                and i.cexpr.y.x.op is idaapi.cot_obj
                and idaapi.get_name(i.cexpr.y.x.obj_ea) == "rvalue_array"
            ):
                i.replace_by(create_dummy_hexrays_insn())
                changed = True
        except Exception as _:
            pass

        return changed

    def remove_instruction(self, inin):
        inin.cleanup()
        inin.replace_by(create_dummy_hexrays_insn())

        self.modified = True

    def remove_noisy_function_calls(self, i):
        if (
            i.cexpr
            and i.cexpr.x
            and idaapi.get_name(i.cexpr.x.obj_ea)
            in [
                "noisy_set_stracktrace",
                "noisy_set_array_owner",
                "RValue_Free",
                "PushContextStack",
                "PopContextStack",
                "RValue_Reset",
            ]
        ):
            self.remove_instruction(i)
            return True

        if (
            i.cexpr
            and i.cexpr.x
            and idaapi.get_name(i.cexpr.x.obj_ea)
            in [
                "vector_constructor_iterator",
                "??_L@YAXPEAX_K1P6AX0@Z2@Z",  # mangled equivalent of the above
                "vector_destructor_iterator",
                "??_M@YAXPEAX_K1P6AX0@Z@Z",  # mangled equivalent of the above
            ]
        ):
            self.remove_debug_prolog()

            self.remove_instruction(i)
            return True

        return False

    def remove_free_rvalue_if_branches(self, i):
        changed = False

        if i.op == ida_hexrays.cit_if:
            if_statement = i.cif
            if_body = if_statement.ithen

            instruction_count_inside_block = len(if_body.cblock)

            for stmt in if_body.cblock:
                if stmt.op == ida_hexrays.cit_expr:
                    expr = stmt.cexpr
                    if expr.op == ida_hexrays.cot_call:
                        # print(idaapi.get_name(expr.x.obj_ea))
                        func_name = idaapi.get_name(expr.x.obj_ea)
                        if func_name == "FREE_RValue_Pre":
                            self.remove_instruction(stmt)
                            instruction_count_inside_block -= 1
                            changed = True

            if instruction_count_inside_block <= 0:
                self.remove_instruction(i)

        return changed


def clean_gml_decompilation():
    vu = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())

    # DebugVisitor().apply_to(vu.cfunc.body, None)
    # return
    v = CToGMLVisitor(vu.cfunc, vu)
    v.do_passes()

    # If any modifications were made, refresh the decompilation view
    if v.modified:
        print("Modifications made")

        vu.cfunc.verify(1, True)
        vu.cfunc.remove_unused_labels()

        CleanupVisitor().clean_up(vu.cfunc.body, None)

        vu.refresh_ctext()
    else:
        print("No modifications made")


def init():
    add_hotkey("ctrl+&", fixup_field_names)
    add_hotkey("ctrl+é", get_gml_function_names)
    add_hotkey("ctrl+'", clean_gml_decompilation)
