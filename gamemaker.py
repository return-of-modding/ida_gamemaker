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


class CToGMLVisitor(ida_hexrays.ctree_visitor_t):
    """A visitor that makes the hexray pseudo c decompilation output more like the original GML."""

    def __init__(self, cfunc):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_INSNS)

        self.cfunc = cfunc
        self.modified = False

    def visit_insn(self, insn):
        if self.remove_vector_rvalue_reset_or_free_call(insn):
            return 0

        if self.remove_noisy_function_calls(insn):
            return 0

        if self.simplify_rvalue_set_from_function(insn):
            return 0

        if self.remove_if_checks_related_to_arg_count(insn):
            return 0

        return 0

    def simplify_rvalue_set_from_function(self, insn):
        return False

    def remove_if_checks_related_to_arg_count(self, insn):
        changed = False

        try:
            if insn.op == ida_hexrays.cit_if:
                if_stmt = insn.cif
                then_branch = if_stmt.ithen
                else_branch = if_stmt.ielse

                if (
                    then_branch
                    and else_branch
                    # if ( v11 <= 2 )
                    #     v16 = &rvalue_array;
                    #   else
                    #     v16 = *(v10 + 2);
                    and idaapi.get_name(then_branch.cblock[0].cexpr.y.x.obj_ea)
                    == "rvalue_array"
                ):
                    # print_swig_object_vars(then_branch.cblock[0].cexpr.y.x)
                    # print(idaapi.get_name(then_branch.cblock[0].cexpr.y.x.obj_ea))
                    insn.replace_by(if_stmt.ielse)
                    changed = True
        except Exception as _:
            pass

        return changed

    def remove_insn(self, insn):
        insn.cleanup()
        insn.replace_by(create_dummy_hexrays_insn())

        self.modified = True

    def remove_vector_rvalue_reset_or_free_call(self, insn):
        if insn.cexpr and idaapi.get_name(insn.cexpr.x.obj_ea) in [
            "vector_constructor_iterator",
            "??_L@YAXPEAX_K1P6AX0@Z2@Z",  # mangled equivalent of the above
            "vector_destructor_iterator",
            "??_M@YAXPEAX_K1P6AX0@Z@Z",  # mangled equivalent of the above
        ]:
            self.remove_insn(insn)
            return True

        return False

    def remove_noisy_function_calls(self, insn):
        changed = False

        if insn.op == ida_hexrays.cit_if:
            if_statement = insn.cif
            if_body = if_statement.ithen

            instruction_count_inside_block = len(if_body.cblock)

            for stmt in if_body.cblock:
                if stmt.op == ida_hexrays.cit_expr:
                    expr = stmt.cexpr
                    if expr.op == ida_hexrays.cot_call:
                        # print(idaapi.get_name(expr.x.obj_ea))
                        func_name = idaapi.get_name(expr.x.obj_ea)
                        if func_name == "FREE_RValue_Pre":
                            self.remove_insn(stmt)
                            instruction_count_inside_block -= 1
                            changed = True

            if instruction_count_inside_block <= 0:
                self.remove_insn(insn)

        return changed


def clean_gml_decompilation():
    vu = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())

    # DebugVisitor().apply_to(vu.cfunc.body, None)
    # return
    v = CToGMLVisitor(vu.cfunc)
    v.apply_to(vu.cfunc.body, None)

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
