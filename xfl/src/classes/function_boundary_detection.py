import context
from classes.ghidra import Ghidra

class FB():
    def __init__(self):
        pass

    def ghidra_extract_function_boundaries(self, path:str, dyn:bool):
        G = Ghidra()
        return G.run_fb_analysis(path, dyn)

    #Extract static function symbols from dynamic symtab. Messed up binaries
    def objdump_extract_symbols_from_dynsym(self):
        self.symbols = []
        objd_p = subprocess.Popen(["objdump", "-T", self.path],
                stdout=subprocess.PIPE, stderr=None)
        buff = objd_p.stdout.read().decode('ascii')
        objd_p.terminate()
        objd_p.wait()
        objd_p.stdout.close()
        lines = buff.split('\n')
        #check symtab was correctly read
        assert( lines[3].split() == ["DYNAMIC", "SYMBOL", "TABLE:"] )

        sym_re_str = r'^([0-9a-z]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([0-9a-z]+)\s+([^\s]+)$'
        sym_re = re.compile(sym_re_str, re.MULTILINE)

        static_symbols = sym_re.findall("\n".join(lines[3:]))

        symbols = []

        for symbol in static_symbols:
            (address, binding, type, section, size, name) = symbol

            vaddr   = int(address, 16)
            sz      = int(size, 16)

            if vaddr == 0 or sz == 0 or "F" not in type:
                #only function symbols
                #i.e. if not "F", skip
                continue

            s = Symbol( name = name,
                    bin_name = self.name,
                    path = self.path,
                    size = sz,
                    vaddr = vaddr,
                    optimisation = self.optimisation,
                    compiler = self.compiler,
                    linkage = self.linkage,
                    type = "symtab",
                    arch=self.arch)

            symbols.append(s)
        self.symbols = symbols


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

        symbols = []

        for symbol in static_symbols:
            (address, binding, type, section, size, name) = symbol

            vaddr   = int(address, 16)
            sz      = int(size, 16)

            if vaddr == 0 or sz == 0 or "F" not in type:
                #only function symbols
                #i.e. if not "F", skip
                continue

            s = Symbol( name = name,
                    bin_name = self.name,
                    path = self.path,
                    size = sz,
                    vaddr = vaddr,
                    optimisation = self.optimisation,
                    compiler = self.compiler,
                    linkage = self.linkage,
                    type = "symtab", 
                    arch=self.arch)

            symbols.append(s)
        self.symbols = symbols

    def r2_extract_function_bonudaries(self, analysis_level=2):
        #pipe = r2pipe.open(self.path, ["-2"])
        self.r2_hdlr.cmd("a"*analysis_level)

        #analyse based on function preludes!
        self.r2_hdlr.cmd("aap")
        symbols = json.loads(self.r2_hdlr.cmd("aflj"))

        desyl_syms = []

        #Get CFG for each function
        for symb in symbols:

            #functions and symbols are different. If the function is an explicit symbol, then its a symb else func
            if symb['type'] != u'fcn' and symb['name'] != u'main': #main is a symbol
                continue

            #Could also use agj addr
            #TODO afi has "address" prop
            addr = symb['offset'] #offset from 0?

            #TODO bytes
            s = Symbol( name = symb['name'],
                    bin_name = self.name,
                    path = self.path,
                    size = symb['size'],
                    vaddr = symb['offset'],
                    optimisation = self.optimisation,
                    compiler = self.compiler,
                    linkage = self.linkage,
                    type = "inferred-r2")

            #NB: size vz realsz -> realsz is the sum of sizes of all basic blocks in func
            #cc -> cyclomatic complexity
            #cost -> cyclomatic cost
            #ebbs -> end basic blocks
            #nbbs -> num basic blocks
            #s.nargs = symb['nargs']
            #s.nlocals = symb['nlocals']
            #s.num_bbs = symb['nbbs']
            #s.end_bbs = symb['ebbs']
            #s.indegree = symb['indegree']
            #s.outdegree = symb['outdegree']
            #s.edges = symb['edges']
            #s.cc = symb['cc']
            #s.cost = symb['cost']
            #s.cfg = pipe.cmd("ag " + hex(symb['offset']))

            desyl_syms.append(s)

        #print("[+] Functions found and analysed: " + str( len( desyl_syms ) ) )
        self.symbols += desyl_syms
        #pipe.quit()

    def nucleus_extract_function_boundaries(self):
        self.symbols = []

        #LIMIT SYMBOLS TO .text section
        objdump_p = subprocess.Popen(["objdump", "-h", 
            self.path], stdout=subprocess.PIPE, stderr=None)
        objd_buff = objdump_p.stdout.read().decode('ascii')
        objdump_p.terminate()
        objdump_p.wait()
        objdump_p.stdout.close()

        text_section_re_str = r'^\s+\d+\s+\.text\s+([0-9a-z]+)\s+([0-9a-z]+)'
        text_sec_re = re.compile(text_section_re_str, re.MULTILINE)
        text_section = text_sec_re.findall(objd_buff)
        assert(len(text_section) == 1)

        (text_section_size, text_section_addr) = int(text_section[0][0], 16), int( text_section[0][1], 16)

        #print(text_section_addr)
        #print(text_section_size)

        symbs = []

        nucleus_p = subprocess.Popen(["nucleus", "-w", "-e",  
            self.path, "-d", "linear", "-f"], stdout=subprocess.PIPE, stderr=None)
        buff = nucleus_p.stdout.read().decode('ascii')
        nucleus_p.terminate()
        nucleus_p.wait()
        nucleus_p.stdout.close()
        #nucleus_p.stderr.close()

        for line in buff.split('\n'):
            if len(line) == 0:
                continue
            so = line.split('\t')
            vaddr = int(so[0], 16)
            size = int(so[1], 10)

            if vaddr < text_section_addr or vaddr > (text_section_addr + text_section_size):
                #don't parsing symbols outside of thisobjects .text section
                #add librarys as seperate objects
                continue

            #max symbol size 64K
            if size == 0 or vaddr == 0:
                continue

            #truncate size to 32K bytes in size > 64K
            if size > 2 ** 16:
                #probably wrong
                size = 2 ** 15

            #TODO bytes
            s = Symbol( name = "fcn." + so[0],
                    bin_name = self.name,
                    path = self.path,
                    size = size,
                    vaddr = vaddr,
                    optimisation = self.optimisation,
                    compiler = self.compiler,
                    linkage = self.linkage,
                    type = "FUNC", 
                    arch=self.arch,
                    binding="GLOBAL")

            #s.save_to_db(db)
            symbs.append(s)
        known_addrs = list(map( lambda x: x.vaddr, self.symbols) )
        found_addrs = list(map( lambda x: x.vaddr, symbs) )

        """
        difference between symbs
        for s in known_addrs:
            if s not in found_addrs:
                ss = list( filter( lambda x: x.vaddr == s, self.symbols) )
                print(ss[0])
        """

        self.symbols += symbs


