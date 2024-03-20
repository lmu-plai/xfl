
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

import context
from elftools.elf.elffile import ELFFile
import IPython
import subprocess
import re

class DwarfInfo():

    def __init__(self, binary):
        self.binary         = binary
        self.top_die        = None
        self.offset_table   = None

        self.prototypes = self.process_dwarf()

    def build_offset_table(self, top_die):
        offset_table = {}

        for die in top_die.iter_children():
            offset_table[die.offset] = die

        return offset_table


    def lookup_type(self, die, offset_table):
        if "DW_AT_type" not in die.attributes:
            return "unknown"
        type_offset = die.attributes["DW_AT_type"].value

        if type_offset not in offset_table.keys():
            return "unknown"

        dwarf_type = offset_table[type_offset]

        if dwarf_type.tag == "DW_TAG_pointer_type":
            return "*" + self.lookup_type(dwarf_type, offset_table)
        elif "DW_AT_name" not in dwarf_type.attributes.keys():
            return "const " + self.lookup_type(dwarf_type, offset_table)
        else:
            return bytes.decode(dwarf_type.attributes["DW_AT_name"].value)


    def find_func_prototypes(self, die, offset_table, prototypes=None):
        if prototypes is None:
            prototypes = {}

        if die.tag == "DW_TAG_subprogram":
            if "DW_AT_name" not in die.attributes:
                for child in die.iter_children():
                    prototypes = self.find_func_prototypes(child, offset_table, prototypes)
                return prototypes

            func_name = bytes.decode(die.attributes["DW_AT_name"].value)

            prototype = {}
            # Lookup return type
            if "DW_AT_type" in die.attributes:
                prototype["return"] = self.lookup_type(die, offset_table)

            # Get parameters and lookup types
            if "DW_AT_prototyped" in die.attributes:
                params = []

                if func_name == "strlen":
                    print(func_name)
                    IPython.embed()

                for child in die.iter_children():
                    if child.tag == "DW_TAG_formal_parameter":
                        params.append(self.lookup_type(child, offset_table))

                prototype["params"] = params

                prototypes[func_name] = prototype

        for child in die.iter_children():
            prototypes = self.find_func_prototypes(child, offset_table, prototypes)

        return prototypes


    def to_json(self, func_dict, pretty):
        if pretty:
            func_json = json.dumps(func_dict, sort_keys=True, indent=2)
        else:
            func_json = json.dumps(func_dict)

        return func_json

    def process_dwarf(self):
        with open(self.binary.path, "rb") as f:
            elffile = ELFFile(f)

            if not elffile.has_dwarf_info():
                raise RuntimeError("File {} has no DWARF data".format(self.binary.path))

            dwarf_info = elffile.get_dwarf_info()

            # Table mapping offset values to the DIEs that they represent
            offset_table = {}
            proto_dict = {}

            IPython.embed()
            for CU in dwarf_info.iter_CUs():
                print("Found compilation unit at", hex(CU.cu_offset))
                try:
                    top_DIE = CU.get_top_DIE()

                    offset_table.update(self.build_offset_table(top_DIE))
                    proto_dict.update(self.find_func_prototypes(top_DIE, offset_table))
                except Exception as e:
                    print(e)
                    print("Exception processing DWARFInfo")

            return proto_dict

    @staticmethod
    def objdump_get_func_prototypes(path):
        "Contents of the .debug_info section:"

        objd_p = subprocess.Popen(["objdump", "--dwarf", path],
                stdout=subprocess.PIPE, stderr=None)
        buff = objd_p.stdout.read().decode('ascii')
        objd_p.terminate()
        objd_p.wait()
        objd_p.stdout.close()
        sections = buff.split('Contents of the ')
        section = None
        for s in sections:
            if s[:11] == ".debug_info":
                section = s
                break

        if not section:
            raise RuntimeError("Binary has no .debug_info section")

        dies = {}
        #die_re = re.compile(r'<([0-9a-fA-F]+)><([0-9a-fA-F]+)>:')
        die_re = re.compile(r'<1><([0-9a-fA-F]+)>:')
        prev_k, prev_v = None, None
        for m in die_re.finditer(section):
            k = m.group(1)
            s = m.span()
            v = s[1] + 1
            b = s[0]
            if prev_k:
                dies[prev_k] = section[prev_v:b]

            prev_k = k
            prev_v = v

        functions = []
        for k, v in dies.items():
            if "DW_TAG_subprogram" in v:

                
                subdie_re = re.compile(r'<([0-9a-fA-F]+)><([0-9a-fA-F]+)>:')
                matches = subdie_re.finditer(v)
                subdies = []
                last = 0
                for m in matches:
                    s,e = m.span()
                    if m.group(1) == '2':
                        subdies.append( v[last:s] )
                    last = e
                subdies.append(v[last:])

                func_die    = subdies[0]
                child_dies  = subdies[1:]


                if "DW_AT_prototyped" in func_die and "DW_AT_name" in func_die:
                    name = DwarfInfo._objdump_extract_name(func_die)

                    ret = ""
                    if "DW_AT_type" in v:
                        ret = DwarfInfo._objdump_extract_type(dies, func_die)

                    params = []
                    for d in child_dies:
                        if "DW_TAG_formal_parameter" in d:
                            d_name        = DwarfInfo._objdump_extract_name(d)
                            type_name   = DwarfInfo._objdump_extract_type(dies, d)
                            params.append( (d_name, type_name) )

                    lib_obj = {
                        'name'      : name,
                        'return'    : ret,
                        'params'    : params
                    }
                    functions.append(lib_obj)
        return functions

    @staticmethod
    def _objdump_extract_type(g_die, die):
        try:
            subdie = DwarfInfo._objdump_extract_type_die(die)
            if "DW_TAG_pointer_type" in g_die[subdie]:
                return "*" + DwarfInfo._objdump_extract_type(g_die, g_die[subdie])
            return DwarfInfo._objdump_extract_name(g_die[subdie])
        except Exception as e:
            return "void"


    @staticmethod
    def _objdump_extract_type_die(die):
        type_re = re.compile(r'^.*DW_AT_type.*:\s<0x([0-9a-fA-F]+)>$', re.MULTILINE)
        m = type_re.search(die)
        if not m:
            raise RuntimeError("Could not match type in die:\n\n {}".format(die))
        return m.group(1)



    @staticmethod
    def _objdump_extract_name(die):
        name_re = re.compile(r'^.*DW_AT_name.*:\s(.*)$', re.MULTILINE)
        m = name_re.search(die)
        if not m:
            raise RuntimeError("Could not match name in die:\n\n {}".format(die))
        return m.group(1)

if __name__ == "__main__":
    obj = type('', (), {})()
    obj.path = '/root/desyl/res/dbg_elf_bins/musl/lib/x86_64-linux-musl/libc.so'
    #dbg = DwarfInfo(obj)
    DwarfInfo.objdump_get_func_prototypes(obj.path)
