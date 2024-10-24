import idaapi
import idautils
import ida_kernwin
import ida_xref
import ida_bytes
import ida_nalt
import ida_name
import idc

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
            string_field_strlit = ida_bytes.get_strlit_contents(string_field_const_char_ptr, -1, ida_nalt.STRTYPE_TERMCHR)
            if string_field_strlit is not None and len(string_field_strlit) > 0:
                string_field = string_field_strlit.decode('ascii')
                print(string_field)

                int_index_address = current_address + 8
                ida_name.set_name(int_index_address, "_" + string_field + "_")

            current_address += 16
        else:
            print("Couldn't fix up field names at address " + "0x{:X}".format(current_address) + " (most likely end of the array, jump to it and continue there until the next array block)")
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
                    op = insn.ops[1]  # Typically LEA has the address in the second operand

                    if op.type == idaapi.o_mem or op.type == idaapi.o_displ:  # Memory or displacement type
                        pointed_addr = idc.get_operand_value(ea, 1)  # Get the address it points to
                        # Try to retrieve a string from the pointed address
                        pointed_str = idc.get_strlit_contents(pointed_addr)
                        if pointed_str:
                            pointed_str_utf8 = pointed_str.decode('utf-8')
                            if pointed_str_utf8 and (pointed_str_utf8.startswith("gml_Script_") or pointed_str_utf8.startswith("gml_Object_")):
                                # print(f"Function {pointed_str_utf8} at: {hex(func_ea)}")
                                idaapi.set_name(func_ea, pointed_str_utf8, idaapi.SN_FORCE)
                                # return
                
                # Move to the next instruction
                ea = idc.next_head(ea)
            else:
                # If the instruction can't be decoded, break the loop
                break

def init():
    add_hotkey("ctrl+&", fixup_field_names)
    add_hotkey("ctrl+é", get_gml_function_names)

