
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, Tristan Benoit, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

import re
from collections import namedtuple
import subprocess
from tqdm import tqdm
from IPython import embed
from ghidra import Ghidra
from config import Config
import utils

class FunctionBoundaryDetection():
    """
        Methods of extracting function boundaries should return the tuple (vaddr, size, name)
        ideally, as a generator
    """
    def __init__(self, config):
        utils._desyl_init_class_(self, config)
        pass

    def ghidra_extract_function_boundaries(self, path:str, dyn:bool):
        """
            Returns vaddr, size tuple
        """
        G = Ghidra(self.config)
        return G.run_fb_analysis(path, dyn)

    #Extract static function symbols from dynamic symtab. Messed up binaries
    def objdump_extract_symbols_from_dynsym(self):
        self.symbols = []
        objd_p = subprocess.Popen(["objdump", "-T", self.path],
                stdout=subprocess.PIPE, stderr=None)
        buff = objd_p.stdout.read().decode('ascii')
        objd_p.terminate()
        objd_p.wait()
        # log to logging
        lines = buff.split('\n')

        for line in lines:
            self.config.debug(line)
        self.config.debug(objd_p.stderr)
        objd_p.stdout.close()
        #check symtab was correctly read
        assert( lines[3].split() == ["DYNAMIC", "SYMBOL", "TABLE:"] )

        sym_re_str = r'^([0-9a-z]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([0-9a-z]+)\s+([^\s]+)$'
        sym_re = re.compile(sym_re_str, re.MULTILINE)

        static_symbols = sym_re.findall("\n".join(lines[3:]))

        for symbol in static_symbols:
            (address, binding, type, section, size, name) = symbol

            vaddr   = int(address, 16)
            sz      = int(size, 16)

            if vaddr == 0 or sz == 0 or "F" not in type:
                #only function symbols
                #i.e. if not "F", skip
                continue

            yield (vaddr, sz, name)



    #Extract symbols after performing analysis on binary
    def objdump_extract_symbols_from_symtab(self):
        self.symbols = []
        objd_p = subprocess.Popen(["objdump", "-t", self.path],
                stdout=subprocess.PIPE, stderr=None)
        buff = objd_p.stdout.read().decode('ascii')
        objd_p.terminate()
        objd_p.wait()
        objd_p.stdout.close()
        lines = buff.split('\n')
        #check symtab was correctly read
        assert( lines[3].split() == ["SYMBOL", "TABLE:"] )

        sym_re_str = r'^([0-9a-z]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([0-9a-z]+)\s+([^\s]+)$'
        sym_re = re.compile(sym_re_str, re.MULTILINE)

        static_symbols = sym_re.findall("\n".join(lines[3:]))

        for symbol in static_symbols:
            (address, binding, type, section, size, name) = symbol

            vaddr   = int(address, 16)
            sz      = int(size, 16)

            if vaddr == 0 or sz == 0 or "F" not in type:
                #only function symbols
                #i.e. if not "F", skip
                continue

            yield (vaddr, sz, name)


    def r2_extract_function_bonudaries(self, b, analysis_level=2, predefined_symbols=None):
        #pipe = r2pipe.open(self.path, ["-2"])

        """
        if predefined_symbols:
            for name, vaddr in tqdm(predefined_symbols, desc="Adding predefined symbols"):
                #add to r2
                #b.r2_hdlr.cmd("f sym.{} @ {}".format(name, hex(vaddr)))
                b.r2_hdlr.cmd("af sym.{} @ {}".format(name, hex(vaddr)))

        self.logger.info("Running Radare2 analysis... (this may take a while)")
        b.r2_hdlr.cmd("a"*analysis_level)
        """

        #analyse based on function preludes!
        self.logger.info("Analysing function preludes...")
        b.r2_hdlr.cmd("aap")

        #self.logger.info("Saving Radare2 Project under `{}`".format(b.name))
        #b.r2_hdlr.cmd("Ps {}".format(b.name))

        self.logger.info("Extracting function boundaries...")
        ##times out on large binaries
        #symbols = json.loads(b.r2_hdlr.cmd("aflj"))
        #symbols = json.loads(b.r2_hdlr.cmd("fnj"))

        symbols = b.r2_hdlr.cmd("afl").split('\n')

        ###for cmd 'afl'
        for line in tqdm(symbols, desc="Filtering functions"):
            #functions and symbols are different. If the function is an explicit symbol, then its a symb else func
            try:
                vaddr, bbs, size, name = line.strip().split()
                vaddr   = int(vaddr, 16)
                size    = int(size)
                yield (vaddr, size, name)
            except:
                pass



        #below is afln analysis
        #"""
        """
        for symb in tqdm(symbols, desc="Filtering functions"):
            #functions and symbols are different. If the function is an explicit symbol, then its a symb else func
            if symb['type'] != u'fcn' and symb['name'] != u'main': #main is a symbol
                continue


            #Could also use agj addr
            #TODO afi has "address" prop
            vaddr = symb['offset'] #offset from 0?
            funcs.append([vaddr, symb['size'], symb['name']])

        return funcs, objects
        """
        #"""

        """
        for symb in tqdm(symbols, desc="Filtering functions"):
            size    = symb['size']
            vaddr   = symb['offset']

            ##string data object
            if symb['name'][:4] == 'str.':
                ##add size to objects
                name    = symb['name'][4:]
                objects.append([vaddr, size, name])

            if symb['name'][:4] == 'sym.':
                name    = symb['name'][4:]
                #add size to functions
                funcs.append([vaddr, size, name])

        """
        return funcs, objects

    def nucleus_extract_function_boundaries(self, path: str):
        #TODO: extract using -f option would take a lot less time
        self.logger.info("Extracting function boundaries with nucleus...")
        nucleus_p = subprocess.Popen(["sh", "-c", self.config.analysis.binary.nucleus_cmd_prefix +" "+
            self.config.desyl + "/deps/nucleus/nucleus -w -p -e \"" + path + "\" -d linear"],
            stdout=subprocess.PIPE, stderr=None)
        buff = nucleus_p.stdout.read().decode('ascii')
        nucleus_p.terminate()
        nucleus_p.wait()
        nucleus_p.stdout.close()
        self.logger.info("Done! Finished extracting function boundaries with nucleus.")

        return FunctionBoundaryDetection._nucleus_parse_function_boundaries(buff.split('\n'))


    def _nucleus_parse_function_boundaries(lines):
        """
            Parse nucleus log file
            e.g.
                function 48841: entry@0xffffffff828a1131 321 bytes
        """
        nucleus_function_re = re.compile(r'^function\s(\d+):\sentry@(.+)\s(\d+)\sbytes$')
        for line in lines:
            line    = line.strip()
            m       = nucleus_function_re.match(line)
            if not m:
                continue

            #name is random count
            name    = m.group(1)
            vaddr   = int(m.group(2), 16)
            size    = int(m.group(3))
            yield vaddr, size, name

    def nucleus_preextracted_function_boundaries(self, path: str):
        lines = utils.read_file_lines(path)
        return FunctionBoundaryDetection._nucleus_parse_function_boundaries(lines)

    def bap_extract_function_boundaries(self, path: str, base_address: int):
        """
            Parse bap output of symbol boundaries
            e.g., (sub_6020 24710 24714)
        """
        self.logger.info("Extracting function boundaries from BAP. For large files this may take a while...")
        proc = subprocess.Popen(["bap", path, "--pass=dump-symbols"],
                stdout=subprocess.PIPE, stderr=None)
        buff = proc.stdout.read().decode('ascii')
        proc.terminate()
        proc.wait()
        proc.stdout.close()
        lines = buff.split('\n')
        bap_symbol_re   = re.compile(r'^\(([^\s]+)\s(\d+)\s(\d+)\)$')

        symbols = {}
        FB = namedtuple('FunctionBoundary', ['start', 'end'])

        for line in lines:
            m   = bap_symbol_re.match(line)
            if m:
                name    = m.group(1)
                start   = int(m.group(2)) - base_address
                end     = int(m.group(3)) - base_address

                if name[:3] != "sub":
                    continue

                # if size is 0, not a real function, skip
                if start == end:
                    continue

                # expand symbol vadr ranges
                if name in symbols:
                    if symbols[name].start > start:
                        symbols[name]._replace(start=start)

                    if symbols[name].end < end:
                        symbols[name]._replace(end=end)
                else:
                    fb = FB(start, end)
                    symbols[name] = fb

        # emit function boundaries
        for key, value in symbols.items():
            yield value.start, value.end - value.start, f"func.{hex(value.start)}"

    def bap_from_file(self, path: str):
        """
            Read symbols from bap output to file
            e.g., $ bap vmlinux-5.4.0-90-generic --pass=dump-symbols > /tmp/vmlinux-5.4.0-90-generic.symbols
        """
        lines           = utils.read_file_lines(path)
        bap_symbol_re   = re.compile(r'^\(([^\s]+)\s([-\d]+)\s([-\d]+)\)$')

        for line in lines:
            m   = bap_symbol_re.match(line)
            if m:
                name    = m.group(1)
                start   = int(m.group(2))
                end     = int(m.group(3))

                if (start < 0):
                    start_bytes    = start.to_bytes(8, byteorder='big', signed=True)
                    start          = int.from_bytes(start_bytes, byteorder='big')

                if (end < 0):
                    end_bytes    = end.to_bytes(8, byteorder='big', signed=True)
                    end          = int.from_bytes(end_bytes, byteorder='big')

                yield start, end - start, name


if __name__ == '__main__':
    config  = Config()
    FB = FunctionBoundaryDetection(config)
    embed()
