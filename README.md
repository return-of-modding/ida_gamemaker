Repository holding some IDA Python Scripts for reverse engineering game maker more easily.

- `init.py` is there for hot reloading `gamemaker.py` (or other modules really)

- `gamemaker.py` currently has a keybind for mass renaming field accesses in gml scripts, by putting the cursor at the beginning of the array in the .data section that hold the tuples of string names <-> field int indices