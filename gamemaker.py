import idaapi
import ida_kernwin
import ida_xref
import ida_bytes
import ida_nalt
import ida_name

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

    

def init():
    add_hotkey("ctrl+&", fixup_field_names)

