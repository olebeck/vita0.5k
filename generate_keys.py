#!/bin/python3
import sys
from types import ModuleType
import requests
import binascii

# ...shut up its awful and i know it

def load_scetypes():
    m = compile(requests.get("https://raw.githubusercontent.com/mathieulh/sceutils/master/scetypes.py").text, "scetypes.py", "exec")
    scetypes = ModuleType("scetypes")
    exec(m, scetypes.__dict__)
    sys.modules["scetypes"] = scetypes
load_scetypes()

exec(requests.get("https://raw.githubusercontent.com/mathieulh/sceutils/master/keys_external.py").text)



o = open("src/_keys.h", "w")

indent = 0

def write(text: str):
    o.write(("\t" * indent) + text + " \\\n")

o.write("#define KEYS {")

def b2_hex(b: bytes):
    h = binascii.b2a_hex(b).decode("ascii")
    o = "{"
    for i in range(len(b)):
        o += "0x" + h[i*2:i*2+2] + ","
    return o + "}"

for type_i, (keytype, key_items) in enumerate(SCE_KEYS._store.items()):
    indent += 1
    write(f"{'{'}KeyType::{keytype.name}, {'{'}")
    for sce_i, (scetype, sce_items) in enumerate(key_items.items()):
        indent += 1
        write(f"{'{'}SceType::{scetype.name}, {'{'}")
        for self_i, (selftype, self_items) in enumerate(sce_items.items()):
            indent += 1
            write(f"{'{'}SelfType::{selftype.name}, {'{'}")

            indent += 1
            for item in self_items:
                write(f"{'{'}")
                indent += 1
                minver = f"{item.minver:x}"[:16]
                maxver = f"{item.maxver:x}"[:16]
                write(f".minver = 0x{minver},")
                write(f".maxver = 0x{maxver},")
                write(f".keyrev = {item.keyrev},")
                write(f".key = {b2_hex(item.key)},")
                write(f".iv = {b2_hex(item.iv)},")
                indent -= 1
                write(f"{'}'}{',' if not item == self_items[-1] else ''}")
            indent -= 1
            write(f"{'}}'}{','}")
            indent -= 1

        write(f"{'}}'}{','}")
        indent -= 1

    write(f"{'}}'}{',' if type_i < len(SCE_KEYS._store)-1 else ''}")
    indent -= 1

o.write("}\n")
o.close()
