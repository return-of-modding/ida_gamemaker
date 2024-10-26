Repository holding some IDA Python Scripts for reverse engineering game maker more easily.

- `init.py` is there for hot reloading `gamemaker.py` (or other modules really)

- `gamemaker.py` currently has:

  - A keybind for mass renaming field accesses in gml scripts, by putting the cursor at the beginning of the array in the .data section that hold the tuples of string names <-> field int indices

  - A keybind for mass renaming gml function names.

  - A keybind for cleaning up the hexray decompilation output so that it's easier to read.

# Usage

IDA -> File -> Script File -> init.py

# Developing

Usage of [HRDevHelper](https://github.com/patois/HRDevHelper) highly recommended.