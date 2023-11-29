import idaapi
import gamemaker

def reload_script():
    gamemaker.cleanup()

    print("Cleaned up")

    idaapi.require("gamemaker")

    gamemaker.init()

    print("Reloaded")

ida_kernwin.add_hotkey("ctrl+\"", reload_script)
