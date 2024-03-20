
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, Tristan Benoit, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

#!/usr/bin/pyhton3
import copy
from random import sample
import json
import os, sys, functools
import r2pipe, rzpipe
import binascii
import subprocess
import math
import hashlib
import lief
import re
import networkx as nx
from networkx.drawing import nx_agraph
from intervaltree import Interval, IntervalTree
import tqdm
import claripy
import numpy as np

from cachetools import cached, LFUCache
from cachetools.keys import hashkey


from config import Config
from symbol import Symbol
from basicblock import BasicBlock
from basicblocksequence import LiveVariableAnalysis, TaintPropagation
from symbolic_execution_engine import SymbolicExecutionEngine
from function_boundary_detection import FunctionBoundaryDetection
import utils
import static_rules
import NLP
import graph_embedding
from archinfo.arch_amd64 import ArchAMD64

from database import PostgresDB

"""
    To print graphs in the terminal use
        
            from asciinet import graph_to_ascii
            print(graph_to_ascii(b.symbols[49].cfg))
"""

def par_analyse_symbol(symbol):
    symbol.analyse()
    return symbol

def par_advanced_symbol_analysis(_b, symbol):
    #sse = copy.deepcopy(_sse)

    config = Config()
    symbol.config = config
    see = SymbolicExecutionEngine(self.config, _b)
    print("Analysing", symbol.name)
    lva = LiveVariableAnalysis(config, symbol)
    tpa = TaintPropagation(config, symbol)
    live_args, live_heap, live_thread_local_storage, live_locals, local_stack_bytes, num_locals, resolved = lva.analyse(see)
    self.logger.debug("Performing Taint Propagation with recovered function arguments and propagated constants")
    flows = tpa.analyse(_b, live_args, resolved=resolved)

    symbol.arguments         = list(live_args)
    symbol.heap_arguments    = list(live_heap)
    symbol.local_stack_bytes            = local_stack_bytes
    symbol.tainted_flows     = flows
    symbol.num_args          = len(live_args)
    symbol.tls               = list(live_thread_local_storage)
    return symbol

class Binary:
        """
            Predefined function prototypes, by analysing a single function at a time we cannot deduce 
            these arguments
        """
        GLOBAL_KNOWN_PROTOTYPES = {
                'memcpy' : { 'name' :'memcpy', 'arguments': [  'rsi', 'rdi', 'rdx' ],
                    'flows': {
                        'rsi': [],
                        'rdi': ['rsi'],
                        'rdx': ['rax']
                        }
                    },
                'memset' : { 'name' :'memset', 'arguments': [  'rsi', 'rdi', 'rdx' ] },
                'setjmp' : { 'name' :'setjmp', 'arguments': [ 'rdi' ] }
        }

        #path argumnet is required
        def __init__(self, config, name="", size=-1, data=b'', symbols=[], objects=[],
                path="", optimisation=-1, compiler="", linkage="", stripped=-1,
                libs=[], must_resolve_libs=True,
                bbs=[], cfg=None, callgraph=None, arch="x86_64", 
                collection_name='', lang=''):

            utils._desyl_init_class_(self, config)
            if not os.path.isfile(path):
                raise Exception("Error, path argument to binary ({}) is not a file!".format(path))

            self.logger.debug("Analysing {}...".format( path ))

            self.path               = path
            self.name               = name
            self.size               = size
            self.libs               = libs
            self.linkage            = linkage
            self.symbols            = symbols
            self.optimisation       = optimisation
            self.linkage            = linkage
            self.compiler           = compiler
            self.data               = data
            self.stripped           = stripped
            self.bbs                = bbs
            self.cfg                = cfg
            self.arch               = arch
            self.callgraph          = callgraph
            self.collection_name    = collection_name
            self.r2_hdlr            = None
            self.lang               = lang
            self.dyn_imports        = []
            self.dyn_objects        = []
            self.dyn_symbol_cache   = {}
            self.sections           = []
            self.objects            = objects


            self.library_ids        = set([])
            """
            Mapper objects allow for lookups based on vaddr
            binary.symbol_mapper[0x4432]
            """
            self.basicblock_mapper  = BasicBlockMapper(self)
            self.symbol_mapper      = SymbolMapper(self)
            self.vaddr_to_name_tree         = IntervalTree()
            self.vaddr_to_real_name_tree    = IntervalTree()

            ##parse file header, check it is a binary
            self.header         = lief.parse(self.path)
            if not self.header:
                raise RuntimeError("Error parsing file header")

            self._infer_bin_type()
            self._infer_binary_params()

            self.entrypoint     = self.header.entrypoint
            if self.bin_format == 'elf':
                self.strings        = self.header.strings

            ##load data sections
            self._r2_fill_sections_data()
            self._build_vaddr_to_section_tree()

            if must_resolve_libs:
                res, missing = self.resolve_linked_libraries()
                self.library_ids = res
                if missing:
                    raise MissingLibrary("Cannot resolve all dynamically linked libraries. ", missing)

            if self.bin_format == 'pe':
                self.logger.warning("Loaded PE file. You may need to manually set `binary.stripped = True` to force function recovery before running `binary.analyse()`")

            # allow for b.bb[0x500] and b.symbol[0x300] maping from vaddrs
            self.bb = BasicBlockMapper(self)
            self.symbol = SymbolMapper(self)

        def _infer_bin_type(self):
            """
                Sets self.bin_type to { 'object', 'executable', 'shared_library' }
            """
            if self.header.format.name == 'ELF':
                # can be executable, dynamic, core, or relocatable
                # if relocatable object file
                if self.header.header.file_type == lief.ELF.E_TYPE.RELOCATABLE:
                    self.bin_type = 'object'
                    return
                
                # if static executable
                elif self.header.header.file_type == lief.ELF.E_TYPE.EXECUTABLE:
                    self.bin_type = 'executable'
                    return

                elif self.header.header.file_type == lief.ELF.E_TYPE.DYNAMIC:
                    if self.header.is_pie:
                        if self.header.has(lief.ELF.DYNAMIC_TAGS.FLAGS_1) and self.header[lief.ELF.DYNAMIC_TAGS.FLAGS_1].value == 1:
                            self.bin_type = 'shared_library'
                            return
                        self.bin_type = 'executable'
                    else:
                        self.bin_type = 'shared_library'

                    return

                elif self.header.header.file_type == lief.ELF.E_TYPE.CORE:
                    self.bin_type = 'core'

                return

        def __getstate__(self):
            utils._desyl_deinit_class_(self)
            if hasattr(self, 'r2_hdlr'):
                del self.r2_hdlr
            return self.__dict__

        def __setstate__(self, state):
            self.__dict__ = state
            utils._desyl_init_class_(self, Config())

        def clone(self):
            return copy.deepcopy(self)

        def __eq__(self, other):
            return self.data == other.data

        @staticmethod
        def caller_vaddr_lookup(db, path, vaddr):
            res = db.client.find_one({ 'path': path, 'vaddr': vaddr}, {'name':1})
            return res['name']

        def md5(self):
            hf = hashlib.md5()
            with open(self.path, "rb") as f:
                c = f.read()
                hf.update(c)
            return hf.hexdigest()

        def sha256(self):
            hf= hashlib.sha256()
            with open(self.path, "rb") as f:
                c = f.read()
                hf.update(c)
            return hf.hexdigest()

        def _clean_lib_name(self, lib):
            """
                Convert libc-2.7.0.so.2.3.0 -> libc
            """
            
            # erase path
            lib = lib.replace("../", "")            
            lib = lib.replace("./", "")
            lib = lib.replace("/", "")
            

            ##special case of ld-inux
            if lib == "ld-linux-x86-64.so.2":
                return lib

            lib_re  = r'^lib(.+?)(?:-[0-9\.]+)*\.so.*$'
            if self.bin_format == 'pe':
                lib_re  = r'^(.*)\.dll$'

            m = re.match(lib_re, lib)
            if not m:
                self.logger.error(f"{m}, {lib}")
                self.logger.error("Error parsing dynamically linked library name!", exc_info=True, stack_info=True)
                raise RuntimeError("Error parsing dynamically linked library name!")

            if self.bin_format == 'pe':
                return re.escape(m.group(1))

            return 'lib' + re.escape(m.group(1))

        def resolve_linked_libraries(self):
            """
                Check that we have a version of the linked libraries required
                to run binary in the database
                :return: (Bool, Missing lib name)
            """
            psql_db = PostgresDB(self.config)
            psql_db.connect()
            curr = psql_db.conn.cursor()
            library_ids = set([])
            shared_lib_ext = '\.so' if self.bin_format == 'elf' else '\.dll'
            for lib in self.libs:
                ##clean lib name
                lib_name = self._clean_lib_name(lib)
                self.logger.info("Dynamically linked library: {} -> {}".format(lib, lib_name))

                if lib_name == "ld-linux-x86-64.so.2":
                    self.logger.info("Assuming ld linux is found")
                    continue

                lib_match_re = r'^' + lib_name + r'[^a-zA-Z]*' + shared_lib_ext + r'.*'

                lib_ids = psql_db.resolve_library(curr, lib_match_re)
                if not lib_ids:
                    ##cannot resolve
                    return False, lib_name
                library_ids |= lib_ids
            return library_ids, None

        def resolve_function_prototype_from_debug_info(self, real_name):
            nlp = NLP.NLP(self.config)
            name = nlp.strip_library_decorations(real_name)
            fsig_re = re.compile(r'(.*)\s\((.*)\);')

            num_funcs = self.r2_hdlr.cmd('afl')
            if num_funcs is None or len(num_funcs) == 0:
                #anal binary
                self.r2_hdlr.cmd('aa')

            funcs = self.r2_hdlr.cmdj('afllj')
            for func in funcs:
                f_name = nlp.strip_library_decorations(func['name'])
                if f_name == name:
                    params = []

                    if 'signature' not in func:
                        self.logger.warning("Signature for function not found! {}".format(func))
                        continue
                    m = re.match(fsig_re, func['signature'])
                    if not m:
                        self.logger.error("Could not match signature regex - {}".format(func['signature']))
                        raise RuntimeError("Could not match r2 func signature regex")

                    ret = "unknown"
                    rets  = m.group(1).split(' ')
                    if len(rets) > 1:
                            ret = rets[0]

                    args = m.group(2).split(',')
                    for param in args:
                        param = param.strip()
                        print(param)
                        if len(param) == 0:
                            continue

                        if param == "...":
                            params.append([ "...", "..." ])
                            continue

                        param_t = param.split()
                        if(len(param_t) <= 1):
                            ###hack, r2 sometimes returns type and name with no spaces
                            ### e.g. "void*addr"
                            param_t = param.split('*')
                            param_t[0] += '*'

                        if(len(param_t) <= 1):
                            print("param_t error")
                            print(param_t)
                        _type = ' '.join(param_t[:-1])
                        _param_name = param_t[-1]
                        pointers = _param_name.count('*')

                        _pn = _param_name.replace('*', '')
                        _t  = _type + '*'*pointers
                        
                        params.append( [ _pn, _t ] )

                    libs_func = { "name" : real_name, "params": params, "return": ret }
                    return libs_func

            self.logger.error("missing lib_func def")
            return False


        def preload_function_prototype_from_db(self):
            if len(self.libs) == 0:
                raise RuntimeError("Error, binary has no imported libraries")

            nlp = NLP.NLP(self.config)
            names = set(map(lambda x: nlp.strip_library_decorations(x['real_name']), self.dyn_imports))

            names -= set(Binary.GLOBAL_KNOWN_PROTOTYPES.keys())
            libs = list(map(lambda x: self._clean_lib_name(x), self.libs))

            db = PostgresDB(self.config)
            db.connect()
            curr    = db.conn.cursor()
            """
            #### Postgres 13 returns an error using batch queries.

            protos = db.batch_resolve_library_prototypes(curr, list(self.library_ids), list(names))

            for n, p in zip(names, protos):
                if not p:
                    self.logger.error("Failed to resolve {} from library {}".format(n, libs))
                    self.logger.error("Assuming no arguments")
                    Binary.GLOBAL_KNOWN_PROTOTYPES[n] = {
                        'real_name': n,
                        'arguments': []
                    }
                    #raise RuntimeError("Failed to resolve {} from library {}".format(n, libs))
                Binary.GLOBAL_KNOWN_PROTOTYPES[ n ] = p
            """
            for name in tqdm.tqdm(names, desc='Resolving dynamically linked function prototypes'):
                proto = db.resolve_dynamic_function(curr, list(self.library_ids), name)
                if not proto:

                    if name[-2:] in ("64", "32"):
                        proto = db.resolve_dynamic_function(curr, list(self.library_ids), name[:-2])
                        if proto:
                            self.logger.debug(f"Failed to resolve {name} from {libs}. Using prototype for {name[:-2]} instead.")
                            Binary.GLOBAL_KNOWN_PROTOTYPES[ name ] = proto
                            continue


                    self.logger.error(f"Failed to resolve {name} from library {libs}. Assuming no arguments...")
                    #raise RuntimeError(f"Failed to resolve {name} from library {libs}. Assuming no arguments...")
                    Binary.GLOBAL_KNOWN_PROTOTYPES[name] = {
                        'real_name': name,
                        'arguments': []
                    }
                else:
                    Binary.GLOBAL_KNOWN_PROTOTYPES[ name ] = proto

        @cached(cache={}, key=lambda self, real_name: hashkey(real_name))
        def resolve_function_prototype_from_db(self, real_name):
            if len(self.libs) == 0:
                raise RuntimeError("Error, binary has no imported libraries")

            nlp = NLP.NLP(self.config)
            name = nlp.strip_library_decorations(real_name)
            
            if real_name in Binary.GLOBAL_KNOWN_PROTOTYPES:
                return Binary.GLOBAL_KNOWN_PROTOTYPES[ real_name ]
            if name in Binary.GLOBAL_KNOWN_PROTOTYPES:
                return Binary.GLOBAL_KNOWN_PROTOTYPES[ name ]

            libs = list(map(lambda x: self._clean_lib_name(x), self.libs))

            #name_re = '(^|[^a-zA-Z]+|_+[a-zA-Z]+_+){}'.format(name)
            name_re = name

            db = PostgresDB(self.config)
            db.connect()
            curr    = db.conn.cursor()
            proto   = db.resolve_dynamic_function(curr, list(self.library_ids), name_re)

            if proto:
                return proto

            self.logger.error("Failed to resolve {} from library {}".format(real_name, libs))
            self.logger.error("Assuming no arguments")
            return {
                'real_name': name,
                'arguments': []
            }
            #raise RuntimeError("Failed to resolve {} from library {}".format(real_name, libs))

        def relabel_symbols_cfg(self, symb_index):
            """
                Relable nodes in CFG from vaddrs to full names '+' vaddrs
            """
            for node in list(self.symbols[symb_index].cfg.nodes()):
                if not isinstance(node, int):
                    continue
                vaddr = int(node)
                locs = self.vaddr_to_real_name_tree.at( vaddr )
                if len(locs) == 0:
                    self.logger.warning("Unknown call/jump to location - {} in {} (parsing vaddrs in CFG)".format(
                        node, self.symbols[symb_index].real_name))
                    utils.nx_set_node_property( self.symbols[symb_index].cfg, node, 'label', "__DESYL_FUNC_UNKNOWN")
                    continue

                for dest in locs:
                    label = dest.data + "+" + hex( vaddr - dest.begin )

                    if hasattr(self.symbols[symb_index].cfg[node], 'label'):
                        ##try find alt label names
                        for i in range(2, 10):
                            if not hasattr(self.symbols[symb_index].cfg[node], 'label_'+ str(i)):
                                utils.nx_set_node_property( self.symbols[symb_index].cfg, node, 'label_'+str(i), label)
                                break
                    else:
                        utils.nx_set_node_property( self.symbols[symb_index].cfg, node, 'label', label)

        def _build_vaddr_to_func_name_tree(self):
            self.vaddr_to_name_tree = IntervalTree()
            self.vaddr_to_real_name_tree = IntervalTree()
            count = 0
            self.logger.debug("[+] Building interval tree of vaddresses to function names")
            for s in tqdm.tqdm(self.symbols, desc="Building function interval tree"):
                ### cannot have 0 range interval
                if s.size > 0:
                    self.vaddr_to_name_tree.addi( s.vaddr, s.vaddr + s.size, s.name )
                    self.vaddr_to_real_name_tree.addi( s.vaddr, s.vaddr + s.size, s.real_name )
                else:
                    self.vaddr_to_name_tree.addi( s.vaddr, s.vaddr + 1, s.name )
                    self.vaddr_to_real_name_tree.addi( s.vaddr, s.vaddr + 1, s.real_name )
                count += 1

            for f in self.dyn_imports:
                if f['size'] > 0:
                    self.vaddr_to_name_tree.addi( f['vaddr'], f['vaddr'] + f['size'], f['name'] )
                    self.vaddr_to_real_name_tree.addi( f['vaddr'], f['vaddr'] + f['size'], f['real_name'] )
                else:
                    self.vaddr_to_name_tree.addi( f['vaddr'], f['vaddr'] + 1, f['name'] )
                    self.vaddr_to_real_name_tree.addi( f['vaddr'], f['vaddr'] + 1, f['real_name'] )
                count += 1

            self.logger.debug("[+] Added {} items to function interval tree".format(count))

        def _build_vaddr_to_data_name_tree(self):
            self.vaddr_to_data_name_tree            = IntervalTree()
            self.vaddr_to_imported_data_name_tree   = IntervalTree()

            for dr in self.objects:
                name    = dr['name']
                vaddr   = dr['vaddr']
                size    = dr['size']
                ### cannot have 0 range interval
                if size > 0:
                    self.vaddr_to_data_name_tree.addi( vaddr, vaddr + size, name )
                else:
                    self.vaddr_to_data_name_tree.addi( vaddr, vaddr + 1, name )

            for dr in self.dyn_objects:
                name    = dr['name']
                vaddr   = dr['vaddr']
                size    = dr['size']
                ### cannot have 0 range interval
                if size > 0:
                    self.vaddr_to_imported_data_name_tree.addi( vaddr, vaddr + size, name )
                else:
                    self.vaddr_to_imported_data_name_tree.addi( vaddr, vaddr + 1, name )

        def _build_vaddr_to_section_tree(self):
            self.vaddr_to_section_tree = IntervalTree()
            #section ( (name, start, end, size, contents) )
            for dr in self.sections:
                name    = dr[0]
                vstart   = dr[1]
                size     = dr[3]

                self.vaddr_to_section_tree.addi( vstart, vstart + size, name )

        def _build_symbol_vaddr_hashmap(self, bbs=[]):
            """
                Store vaddr -> symbol index map 
                build interval tree
            """
            t = IntervalTree()
            for i in range(len(self.symbols)):
                #range is x <= int < y
                #t.addi( self.symbols[i].vaddr, (self.symbols[i].vaddr + self.symbols[i].size + 1), i )
                t.addi( self.symbols[i].vaddr, (self.symbols[i].vaddr + self.symbols[i].size), i )
            self.addr_to_symbol_index_itree = t  

        #Get symbols locations and size, whether the binary is stripped or not
        def find_symbol_index(self, name=False, address=False):
            for i in range(len(self.symbols)):
                if name and not address:
                    if self.symbols[i].name == name:
                        return i
                if address and not name:
                    if self.symbols[i].vaddr == address:
                        return i

                if self.symbols[i].vaddr == address and self.symbols[i].name == name:
                    return i
            return None

        @staticmethod
        def linkage_type(path):
            """
                Read ELF header and check ELF type to be EXEC or Shared Object
            """
            if int( subprocess.check_output('readelf -h {} | grep "Type" | grep EXEC | wc -l'.format(path), shell=True) ) == 1:
                return 'static'
            return 'dynamic'

        def _r2_fill_sections_data(self):
            """
                Find data only sections and read their data
            """
            self.sections = []
            bin_sections = json.loads(self.r2_hdlr.cmd('iSj'))
            #data_section_names = set(['.bss', '.data'])

            #previously limited to data only sections, fill all sections in
            #case of locating data from any section
            #for d_section in list(filter(lambda x: x['name'] in data_section_names, bin_sections)):
            for section in bin_sections:
                    name            = section['name']
                    ##vaddr is negative for windows openbsd kernel
                    vstart          = section['vaddr']

                    if (vstart < 0):
                        self.logger.warning("Error in r2 pipe! Fixing 32 bit signed integer!")
                        vstart_bytes    = vstart.to_bytes(8, byteorder='big', signed=True)
                        vstart          = int.from_bytes(vstart_bytes, byteorder='big')

                    pstart          = section['paddr']
                    size            = section['size']

                    if vstart == 0:
                        ##ignore this section
                        continue

                    if size <= 0:
                        continue

                    contents = self.r2_read_bytes(vstart, size)
                    self.sections.append( (name, vstart, pstart, size, contents) )

        def r2_read_bytes(self, vaddr, size_in_bytes, override_baddr=False):
            """
                Read bytes from binary at vaddr
                Add base address of binary to virtual address
            """
            if size_in_bytes <= 0:
                return bytes()

            # don't add base address for objects
            # fix rizin api
            # if self.bin_type == 'object':
            #    vaddr -= self.base_address

            chunk_size  = 2**16
            if size_in_bytes > chunk_size:
                ##split into chunks
                data    = b''
                for i in range(math.ceil(size_in_bytes / chunk_size)):
                    ##don't read full chunk on final iteration
                    diff    = size_in_bytes - (i*chunk_size)
                    if diff < chunk_size:
                        chunk_size = diff
                        ##don't read full chunk on final iteration
                        ##need to check returned length because r2 api is unstable
                    tdata   = bytes(json.loads(self.r2_hdlr.cmd('pxj {} @ {}'.format(chunk_size, self.base_address + vaddr + (i*chunk_size)))))
                    assert(len(tdata) == chunk_size)
                    data    += tdata
                assert(len(data) == size_in_bytes)
                return data
            data    = bytes(json.loads(self.r2_hdlr.cmd('pxj {} @ {}'.format(size_in_bytes, self.base_address + vaddr))))
            assert(len(data) == size_in_bytes)
            return data


        def _infer_binary_params(self):
            """
                Infer meta-data about binary
            """
            self.name = os.path.basename(self.path)

            ##get file size
            self.size = os.path.getsize(self.path)

            ##refusing to analyse binary above 24MB
            if self.size > 1024 * 1024 * 128:
                raise BinaryTooLarge(self)

            if not self.r2_hdlr:
                if self.config.analysis.binary.USE_RIZIN:
                    self.logger.info("Using Rizin > Radare2!")
                    self.r2_hdlr = rzpipe.open(self.path, ["-2"])
                else:
                    self.r2_hdlr = r2pipe.open(self.path, ["-2"])

            info = self.r2_hdlr.cmdj('iIj')
            self.stripped   = info['stripped']
            self.linkage    = 'static' if info['static'] else 'dynamic'
            self.compiler   = info['compiler'] if 'compiler' in info else 'UNKNOWN'
            self.arch       = info['arch'] + '_' + str(info['bits'])
            self.lang       = info['lang'] if 'lang' in info else 'UNKNOWN'
            self.os         = info['os']
            self.bin_format = info['bintype']
            self.bin_class  = info['class']
            self.base_address = info['baddr']

            ##stripped status is r2 is reported for binaries with symbols
            #if self.stripped:
            #    raise StrippedBinaryError(self)

            ##if compiler is unknown search for it in the path
            if self.compiler == 'UNKNOWN':
                lpath = self.path.lower()
                if '/gcc/' in lpath:
                    self.compiler = 'gcc'
                elif '/clang/' in lpath:
                    self.compiler = 'clang'
                elif '/msvc/' in lpath:
                    self.compiler = 'msvc'
                elif '/icc/' in lpath:
                    self.compiler = 'icc'

            #get dynamic libraries imported
            self.libs = self.r2_hdlr.cmdj("ilj")


            #used for custom file hierarchy
            #set optimisation
            if self.optimisation == -1:
                #m = re.match(r'.*?o(\d{1})\/', self.path)
                m = re.match(r'.*?\/o((\d{1})|(\w{1}))\/', self.path)
                if m:
                    self.optimisation = m.group(1)


        def r2_internal_function_desc(self, r2_funcs, r2_name: str):
            """
                Access Radare2 internal function description for r2 function name
            """
            funcs = list(filter(lambda x: x['name'] == r2_name, r2_funcs))
            if len(funcs) == 1:
                # found singel function
                return funcs[0]
            if len(funcs) == 0:
                return None

            raise RuntimeError(f"Radare2 returned multiple functions for name {r2_name}")

        #Extract symbols after performing analysis on binary
        def r2_extract_symbols(self, exported_only=False):
            """
            Extract FUNC symbols using the r2 API
            Use exported_only=True to limit binding of symbols to GLOBAL or WEAK

            From the ELF Spec, symbols with size 0 have 0 size **or the size is unknown**
            """
            self.symbols = []
            nlp = NLP.NLP(self.config)
            symbols = self.r2_hdlr.cmdj("isj")

            binding = ['GLOBAL', 'WEAK', 'LOCAL']
            if exported_only:
                binding = ['GLOBAL', 'WEAK']

            #static symbols only
            func_symbols = list( filter( lambda x: x['type'] in [ 'FUNC', 'LOOS', 'HIOS'] and 
                #x['size'] > 0 and x['name'][0:4] != "imp." and x['bind'] in [ 'GLOBAL' ]
                x['name'][0:4] != "imp." and x['bind'] in binding
                , symbols))

            for s in func_symbols:
                if s['size'] > 64*1024:
                    raise FunctionTooLarge(self, s['name'], s['size'])


            # cache function dict once
            r2_funcs = self.r2_hdlr.cmdj('aflj')
            for symb in func_symbols:
                symb['signature'] = ''
                symb['noreturn'] = None
                # symbol has size 0 OR size is unknown, need to guess size
                r2_desc = self.r2_internal_function_desc(r2_funcs, symb['flagname'])
                if r2_desc:
                    if symb['size'] == 0:
                        symb['size'] = r2_desc['size']
                    else:
                        self.logger.warning(f"Cannot find size for function {symb['name']} at vaddr {symb['vaddr']}")

                    symb['signature']   = r2_desc['signature']
                    symb['noreturn']    = r2_desc['noreturn'] if 'noreturn' in r2_desc else None

                ##check if symbol is already added
                ## Why? Because r2 API can return same symbol multiple times, multiple symbol definitions
                if len(self.get_symbol_desc({'real_name': nlp.strip_r2_decorations( symb['name'] ), 'size': symb['size'], 'vaddr': symb['vaddr'] })) > 0:
                    continue
				

                s = Symbol(self.config, 
                        name            = nlp.strip_library_decorations( symb['name'] ),
                        real_name       = nlp.strip_r2_decorations( symb['name'] ),
                        bin_name        = self.name,
                        path            = self.path,
                        size            = symb['size'],
                        vaddr           = symb['vaddr'],
                        optimisation    = self.optimisation,
                        data            = self.r2_read_bytes(symb['vaddr'], symb['size']),
                        compiler        = self.compiler,
                        linkage         = self.linkage,
                        type            = symb['type'],
                        binding         = symb['bind'], 
                        signature       = symb['signature'],
                        noreturn        = symb['noreturn'],
                        arch            = self.arch)

                # check r2 is reading data correctly
                if s.data == bytes([0xff]) * s.size and s.size > 32:
                    print("Error, probably incorrect reading of binary data")
                    continue #raise RuntimeError("Error, probably incorrect reading raw bytes, offset error")
                if s.data == bytes([0x00]) * s.size and s.size > 32:
                    print("Error, probably incorrect reading of binary data")
                    continue #raise RuntimeError("Error, probably incorrect reading raw bytes, offset error")

                self.logger.debug("{:<40}->{:>40}".format(symb['name'], s.name))
                s.signature = symb['signature']
                self.symbols.append(s)

        def add_symbols_from_boundaries(self, f_boundaries, can_delay=True):
            """
            Add symbols from an iterable set of function boundaries
            f_boundaries: [ (vaddr:int, size:int) ]
            """
            ##delay adding symbols with very large boundaries, or very small
            delayed_symbols = []

            for vaddr, size, name in f_boundaries:

                ##only update symbol size if it does not completely envelop
                ##other symbols
                symbs   = self.vaddr_to_real_name_tree.envelop(vaddr, vaddr + size)
                if len(symbs) > 1:
                    self.logger.warning("Refusing to add symbol size that\
                            envelops other symbols! {} :: {} :: {}".format(name,
                                vaddr, size))
                    continue
                self.vaddr_to_real_name_tree.addi(vaddr, vaddr + size, name)

                ##check for incorrect function boundaries
                if size > 2**14:
                    ##probably incorrect
                    self.logger.warning("Refusing to add recovered function\
                            with size {}. Too big!".format(size))
                    continue

                if can_delay:
                    ##check for incorrect function boundaries
                    if size > 2**11:
                        ##probably incorrect
                        self.logger.warning("Function boundaries look too big.\
                        Delaying adding until others are processed. Size: {}.".format(size))
                        delayed_symbols.append([vaddr, size, name])
                        continue

                s = Symbol(self.config, 
                        name        = "func.{}".format(vaddr),
                        real_name   = "func.{}".format(vaddr),
                        bin_name    = self.name,
                        path        = self.path,
                        size        = size,
                        vaddr       = vaddr,
                        data        = self.r2_read_bytes(vaddr, size),
                        linkage     = self.linkage,
                        type        = "FUNC",
                        binding     = "UNKNOWN", 
                        arch        = self.arch)

                if ((s.data == bytes([0xff]) * s.size) or (s.data == bytes([0x00]) * s.size)):
                    continue

                self.logger.debug("{:<40}->{:>40}".format(s.real_name, s.name))
                self.symbols.append(s)

            ##call self with delayed symbols
            if len(delayed_symbols) > 0:
                self.add_symbols_from_boundaries(delayed_symbols, can_delay=False)

            ##update mappings
            self._build_vaddr_to_func_name_tree()
            self._build_vaddr_to_data_name_tree()

        def r2_extract_lib_funcs(self):
            """
                Extracts all functions in a .so file with paramateres, return, and locals
            """
            funcs = []
            nlp = NLP.NLP(self.config)
            #if not self.r2_hdlr:
            #    self.r2_hdlr = r2pipe.open(self.path, ["-2"])

            self.logger.debug("Starting r2 advanced analysis")
            self.r2_hdlr.cmdj("aaaa")
            funcs = self.r2_hdlr.cmdj("afllj")

            for func in funcs:
                lib_s = { 'path' : self.path, 'name': func['name'], 
                        'bin_name': os.path.basename(self.path),  
                        'params': func['params'],
                        'return': func['return']
                        }
                #if 'signature' in func
                #lib_symbols.append(lib_s)

            #static symbols only
            func_symbols = list( filter( lambda x: x['type'] in [ 'FUNC', 'LOOS', 'HIOS'] and 
                #x['size'] > 0 and x['name'][0:4] != "imp." and x['bind'] in [ 'GLOBAL' ]
                x['name'][0:4] != "imp." and x['bind'] in [ 'GLOBAL', 'WEAK', 'LOCAL' ]
                , symbols))

            total_symbols = len( func_symbols )
            #print("[+] Total FUNC symbols of non-zero size in binary: " + str( total_symbols ) )

            symbol_prefilter = set([])
            symbol_prefilter_names = {}

            for symb in func_symbols:
                s = Symbol(self.config, 
                        name = nlp.strip_library_decorations( symb['name'] ),
                        real_name = nlp.strip_r2_decorations( symb['name'] ),
                        bin_name = self.name,
                        path = self.path,
                        size = symb['size'],
                        vaddr = symb['vaddr'],
                        optimisation = self.optimisation,
                        data = self.r2_read_bytes(symb['vaddr'], symb['size']),
                        compiler = self.compiler,
                        linkage = self.linkage,
                        type = symb['type'],
                        binding = symb['bind'], 
                        arch=self.arch)

                assert(s.data != bytes([0xff]) * s.size)
                assert(s.data != bytes([0x00]) * s.size)

                self.logger.debug("{:<40}->{:>40}".format(symb['name'], s.name))
                self.symbols.append(s)

        def r2_get_section_range(self, name):
            sections = json.loads( self.r2_hdlr.cmd("iSj") )
            for s in sections:
                if s['name'] == name:
                    return int( s['vaddr'] ), int( s['size'] )

            return False, False

        def r2_extract_xrefs(self, r2_hdlr, symb_real_name):
            data_xrefs, code_xrefs, string_xrefs = set([]), set([]), set([])

            xrefs = json.loads( self.r2_hdlr.cmd('axffj @ sym.{}'.format( s.symb_real_name )) )
            for xref in xrefs:
                if xref['type'] in ['CODE', 'CALL']:
                    code_xrefs.add(xref['ref'])

                elif xref['type'] == 'DATA': 
                    if xref['name'][:4] == 'str.':
                        #strings_xrefs.add( xref['ref'] )
                        string_xrefs.add( self.r2_hdlr.cmd('ps @ {}'.format( xref['ref'] )) )
                    else:
                        data_xrefs.add( xref['ref'] )

            return data_xrefs, code_xrefs, string_xrefs

        def build_callgraph_from_symbols(self, symbols=None):
            """
                Build interprocedural callgraph from analysed symbols
                A subset of the binary callgraph may be produce by passing in 
                a list of symbols
            """
            if not symbols:
                symbols = self.symbols

            callgraph = nx.DiGraph()
            for symbol in symbols:
                #NB: Cannot handle same real_name multiple definitions, need to add vaddr and size + binding?
                #Added this back in to ensure all symbols are in callgraph
                #node_string = hash(symbol.real_name + str(symbol.vaddr) + str(symbol.binding) + str(symbol.size))
                #TODO: append vaddr to callees  (C++ integration)
                if symbol.real_name not in callgraph:
                    callgraph.add_node(symbol.real_name, vaddr=symbol.vaddr, binding=symbol.binding, args=symbol.num_args, size=symbol.size)
                else:
                    self.logger.error("Refusing to overwrite binary calgraph node from previous symbol with name {}".format(symbol.real_name))

            ## now loop again and add callees and callers
            ## second loop stops symbol being added as callee without full information
            for symbol in symbols:
                for caller in symbol.callers:
                    callgraph.add_edge( caller, symbol.real_name )
                for callee in symbol.callees:
                    if callee not in callgraph.nodes:
                        ##add node with vaddr
                        s = self.get_symbol(callee)
                        if not s:
                            print("Cannot resolve symbol {}".format(callee))
                            raise RuntimeError("Cannot resolve symbol {}".format(callee))
                        if not isinstance(s, Symbol):
                            callgraph.add_node(s['real_name'], vaddr=s['vaddr'], binding='GLOBAL', size=s['size'])

                    callgraph.add_edge( symbol.real_name, callee )
            return callgraph

        def build_cfg_from_symbols(self, symbols=None):
            """
                Build basicblock control flow graph from analsed symbols
                A subset of basicblock can be generated by passing in a subset of symbols
            """
            if not symbols:
                symbols = self.symbols

            cfg = nx.DiGraph()
            for symbol in symbols:
                for bb in symbol.bbs:
                    for exit_vaddr, exit_type in bb.exits:
                        if isinstance(exit_vaddr, str):
                            exit_vaddr = "{}::{}".format(bb.vaddr, exit_vaddr)
                        cfg.add_edge(bb.vaddr, exit_vaddr, jumpkind=exit_type)
            return cfg

        def r2_add_objects(self):
            """
            Add symbol objects to binary, global vars
            """
            self.objects    = []
            r_symbols       = self.r2_hdlr.cmdj("isj")
            obj_symbols     = list(filter(lambda x: x['type'] == "OBJ" and "vaddr" in x, r_symbols))
            for s in obj_symbols:
                obj = {
                    'name'  : s['realname'],
                    'vaddr' : s['vaddr'], 
                    'size'  : s['size'],
                    'data'  : self.r2_read_bytes(s['vaddr'], s['size'])
                }
                self.objects.append(obj)
		
        def r2_add_dyn_import_objects(self):
            r_imports   = self.r2_hdlr.cmdj("iij")
            r_imp_objs  = filter(lambda x: x['type'] == "OBJ" and "vaddr" in x, r_imports)
            self.dyn_objects = list(map(lambda x: 
                {
                    'name'  : x['name'], 
                    'vaddr' : x['vaddr'],
                    'size'  : x['size']
                }
            , r_imp_objs ))

        def r2_add_dyn_imports(self):
            """
                Add dynamic imports under self.dyn_imports
                Below uses multiple method because R2/Rizin API is not consistent
            """
            # the address of relocated objects is available with the ir command but not the type of object
            # the type is only avaliable with ii but the relocated address is all 0x0
            self.dyn_imports = []

            nlp = NLP.NLP(self.config)
            # radare2 API keeps changing! ir, ii is buggy
            # combine 2 lists to get both relocated address and func types
            r_imports = self.r2_hdlr.cmdj("iij")
            r_imp_funcs = filter( lambda x: x['type'] == "FUNC" and 'plt' in x, r_imports )
            ri = list(map(lambda x: 
                {
                    'name'  : nlp.strip_library_decorations( x['name'] ), 
                    'real_name'  : nlp.strip_r2_decorations( x['name'] ), 
                    'vaddr' : x['plt'],
                    'size' : 6
                }
            , r_imp_funcs ))

            # If address of import is 0, check relocation table
            relocations = json.loads( self.r2_hdlr.cmd("irj") )
            reloc_funcs = filter( lambda x: 'name' in x and 'vaddr' in x, relocations )
            relocs = dict(map(lambda x:
                            [ nlp.strip_library_decorations( x['name'] ), x['vaddr'] ]
                            , reloc_funcs ))

            for f in ri:
                if f['vaddr'] == 0:
                    # lookup in relocation table
                    if f['name'] in relocs:
                        f['vaddr'] = relocs[f['name']]
                        self.dyn_imports.append(f)
                        continue
                    # raise RuntimeError("Import has vaddr of 0x0000 and we cannot find it in the relocation table " + str(f['name']) + " :: " + str(f['vaddr']))
                    self.logger.error("Import has vaddr of 0x0000 and we cannot find it in the relocation table " + str(f['name']) + " :: " + str(f['vaddr']))
                self.dyn_imports.append(f)

        def _analyse_init(self, exported_only=False, override=True, fbd='ghidra'):
            """
                Extarct functions and data, build internal data structures
                :param exported_only: Limit functions to those exported
                :param override: Overwide symbol table, recover function boundaries
            """
            sys.setrecursionlimit(3500)
            # analyse functions in binary
            # this is needed to find size of symbols with an unknown size e.g. memcpy form libc
            self.logger.debug("R2 analyzing symbols...")
            self.r2_hdlr.cmd('aa')

            ##override previous analysis results
            if override:
                self.logger.debug("Extracting symbols...")
                """
                    Stripped libarraies still contain dynamic symbolic information. The binary is still considered
                    stripped.
                """
                # Windows PE with imported functions are considered not stripped by r2
                # If 0 symbols, consider it stripped
                if self.os == 'windows' and not self.stripped:
                    # extract symbols from header
                    self.r2_extract_symbols(exported_only=exported_only)
                    if len(self.symbols) == 0:
                        self.stripped = True

                if self.stripped and not exported_only:
                    self.logger.info("{} is stripped, extracting function boundaries!".format(self.path))
                    fb = FunctionBoundaryDetection(self.config)
                    if fbd == 'ghidra':
                        f_boundaries = fb.ghidra_extract_function_boundaries(self.path, self.linkage=="dynamic")
                    elif fbd == 'nucleus':
                        f_boundaries = fb.nucleus_extract_function_boundaries(self.path)
                    elif fbd == 'objdump':
                        f_boundaries = fb.objdump_extract_symbols_from_symtab(self.path)
                    elif fbd == 'radare2':
                        f_boundaries = fb.r2_extract_function_boundaries(self.path)
                    elif fbd == 'bap':
                        f_boundaries = fb.bap_extract_function_boundaries(self.path, self.base_address)

                    self.add_symbols_from_boundaries(f_boundaries)

                    if self.os != 'windows':
                        # analyse common routines from static rules
                        self.analyse_identify_static()
                else:
                    #self.dwarf = DwarfInfo(self)
                    self.r2_extract_symbols(exported_only=exported_only)

                self.r2_add_objects()

                ##add other imports for xrefs, plt funcs
                if self.linkage == "dynamic":
                   self.r2_add_dyn_imports()
                   self.r2_add_dyn_import_objects()

            else:
                self.logger.debug("Using symbols previously found in self.symbols")

            self.logger.debug("Found {} .text functions".format(len(self.symbols)))
            self.logger.debug("Found {} objects".format(len(self.objects)))
            self.logger.debug("Found {} imported funcs".format(len(self.dyn_imports)))
            self.logger.debug("Found {} imported objects".format(len(self.dyn_objects)))
            self._build_vaddr_to_func_name_tree()
            self._build_vaddr_to_data_name_tree()

        def _analyse_build_filt(self):
            ##ELF sections start vaddr and size
            text_rg     = self.r2_get_section_range('.text')
            data_rg     = self.r2_get_section_range('.data')
            bss_rg      = self.r2_get_section_range('.bss')
            fini_rg     = self.r2_get_section_range('.fini')
            dynamic_rg  = self.r2_get_section_range('.dynamic')

            text_filt       = lambda x: not (x >= text_rg[0]      and x < (text_rg[0] + text_rg[1]))
            data_filt       = lambda x: not (x >= data_rg[0]      and x < (data_rg[0] + data_rg[1]))
            bss_filt        = lambda x: not (x >= bss_rg[0]       and x < (bss_rg[0] + bss_rg[1]))
            fini_filt       = lambda x: not (x >= fini_rg[0]      and x < (fini_rg[0] + fini_rg[1]))
            dynamic_filt    = lambda x: not (x >= dynamic_rg[0]   and x < (dynamic_rg[0] + dynamic_rg[1]))

            return lambda x: text_filt(x) and data_filt(x) and bss_filt(x) and fini_filt(x) and dynamic_filt(x)


        def _analyse_symbols(self, vex_const_filter):
            """
                Analyse all symbols 
            """
            with tqdm.trange(len(self.symbols), desc='Symbols') as t:
                for sym_index in t:
                    t.set_postfix(name=self.symbols[sym_index].name.ljust(30)[-30:], binary=self.name.ljust(20)[-20:])
                    self.symbols[sym_index].analyse(self, r2_pipe_hdlr=self.r2_hdlr)

                    ##remove constants that reference .text and .data sections
                    self.symbols[sym_index].vex['constants'] = set(filter(vex_const_filter, self.symbols[sym_index].vex['constants']))

                    ## Resolve callee references
                    func_calls = set([])
                    ##filters for vaddrs in callees and tries to resolve the address
                    func_searches = map(lambda x,
                            m=self.vaddr_to_real_name_tree: m.at(x),
                            set(map(lambda x: int(x, 16), self.symbols[sym_index].callees)))

                    for search_res in func_searches:
                        for func in search_res:
                            func_calls.add( func.data )
                    self.symbols[sym_index].callees = func_calls


                    ## Resolve data references
                    data_refs = set([])
                    ##filters for vaddrs in callees and tries to resolve the address
                    data_searches = map(lambda x, m=self.vaddr_to_data_name_tree: m.at(x), self.symbols[sym_index].data_refs)

                    for search_res in data_searches:
                        for interv in search_res:
                            data_refs.add( interv.data )
                    
                    ## Resolve dynamically imported data references
                    dyn_data_refs = set([])
                    ##filters for vaddrs in callees and tries to resolve the address
                    data_searches = map(lambda x, m=self.vaddr_to_imported_data_name_tree: m.at(x), self.symbols[sym_index].data_refs)

                    for search_res in data_searches:
                        for interv in search_res:
                            dyn_data_refs.add( interv.data )

                    ##convert to list for JSON serialisable
                    self.symbols[sym_index].data_refs = list(data_refs)
                                        
                    ##convert to list for JSON serialisable
                    self.symbols[sym_index].imported_data_refs = list(dyn_data_refs)



        def _analyse_add_callers(self):
            ##build callers after resolving all callees
            ##build name to index for fast lookup
            symbol_index_cache = dict(map(lambda x: [x[1].real_name, x[0]], enumerate(self.symbols)))
            for s in tqdm.tqdm(self.symbols, desc="Building Callers"):
                for callee in s.callees:
                    if callee in symbol_index_cache:
                        self.symbols[ symbol_index_cache[callee] ].callers.add( s.real_name )

        def _analyse_advanced(self, see: SymbolicExecutionEngine):
            """
                Analyse function with symbolic execution engine of choice
            """
            for i in tqdm.tqdm(range(len(self.symbols)), desc="Analysing symbols with symbolic memory model"):
                self.logger.debug("Analysing {}".format(self.symbols[i].real_name))

                lva = LiveVariableAnalysis(self.config, self.symbols[i])
                live_args, live_heap, live_thread_local_storage, live_locals, local_stack_bytes, num_locals, resolved = lva.analyse(see)

                self.logger.debug("Performing Taint Propagation with recovered function arguments and propagated constants")
                tpa = TaintPropagation(self.config, self.symbols[i], self)
                flows = tpa.analyse(self, live_args, resolved=resolved)

                self.symbols[i].arguments           = list(live_args)
                self.symbols[i].heap_arguments      = list(live_heap)
                self.symbols[i].tls                 = list(live_thread_local_storage)
                self.symbols[i].locals              = list(live_locals)
                self.symbols[i].local_stack_bytes   = local_stack_bytes
                self.symbols[i].tainted_flows       = flows
                self.symbols[i].num_args            = len(live_args)
                self.symbols[i].num_locals          = num_locals
                self.symbols[i].resolved            = resolved

                ##build much simpler tainted function args structure
                """
                    {
                        'rax': {
                            'malloc'  : ['rax', 'rsi']
                        }
                    }
            
                """
                tainted_args    = {}
                for arg in live_args:
                    f_flows = {}
                    targ_flows = tpa.analyse(self, set([arg]), resolved=resolved)
                    for func, flows in targ_flows:
                        f_flows[func] = set([])
                        for f_t_arg in flows:
                            f_flows[func].add(f_t_arg)

                    tainted_args[arg] = f_flows

                self.symbols[i].tainted_args        = tainted_args

        def _analyse_tainted_function_flows(self):
            #need to reduce set of tainted variables in flows to 
            #that af function arguments for the corresponding function
            for i in tqdm.tqdm(range(len(self.symbols))):
                for j, flow in enumerate(self.symbols[i].tainted_flows):
                    func, args = flow
                    if func == "__FUNC_RET__":
                        self.symbols[i].tainted_flows[j] = (func, list(args & set(['rax', 'xmm0', 'ymm0'])))
                        continue

                    func_args = self.get_func_args(func, real_name=True)
                    args = set(args) & set(func_args)
                    self.symbols[i].tainted_flows[j] = (func, list(args))

                ##remove flows where no args are tainted
                self.symbols[i].tainted_flows = list(filter(lambda x: len(x[1]) > 0, self.symbols[i].tainted_flows))

                # add symbol.return
                # return list of registers that are returned when function returns
                # TODO: this won't catch constant returns, fix this
                ret_flows = list(filter(lambda x: x[0] == '__FUNC_RET__', self.symbols[i].tainted_flows))
                if len(ret_flows) > 0:
                    self.symbols[i].returns = ret_flows[0][1]


        def apply_tainted_flows(self, vaddr:int, tainted:set):
            """
                Recursively apply taint to callee functions with tainted set tainted
            """
            #not implemented
            #return None
            SM  = SymbolMapper(self)
            s   = SM[vaddr]
            print("In apply tainted flows")
            return None
            tainted_args    = s.arguments & tainted
            tainted_subset  = set([])
            #for flow in s.tainted_flows:
            return tainted_subset

        def _analyse_build_callgraph(self):
            """
                Build callgraph and control flow graph for binary
            """
            self.logger.debug("Building callgraph...")
            self.callgraph  = self.build_callgraph_from_symbols()
            self.cfg        = self.build_cfg_from_symbols()

            self.logger.debug("Generating node embeddings")
            ##add node embeddings to each symbol based on binary callgraph
            node_embed_mat, mapping, mod_cg   = graph_embedding.binary_node_embeddings(self, self.callgraph)

            rows, cols  = node_embed_mat.shape
            for i in range(rows):
                node_embedding  = node_embed_mat[i, :]
                symbol_real_name= mapping[i]
                symb_desc   = { 'real_name' : symbol_real_name, 'vaddr': mod_cg.nodes[i]['vaddr'], 'binding': mod_cg.nodes[i]['binding'], 'size': mod_cg.nodes[i]['size'] }
                symbs = self.get_symbol_desc( symb_desc )

                if len(symbs) > 1:
                    self.logger.error("Error finding unique symbol {}".format(symb_desc))
                    raise RuntimeError("Error finding unique symbol {}".format(symb_desc))

                if len(symbs) == 0:
                    ##full symbol desc not found, dynamically imported
                    continue
                
                s = symbs[0]
                ##otherwise dynamically imported symbol
                if isinstance(s, Symbol):
                    s.node_embedding = node_embedding


            ##ensure every symbol has node embedding, create 0 embeddings for other symbols
            for i in range(len(self.symbols)):
                if not hasattr(self.symbols[i], 'node_embedding') or isinstance(self.symbols[i].node_embedding, type(None)):
                    self.logger.error(f'Missing node embedding for symbol: {self.symbols[i].real_name} @ {self.symbols[i].vaddr}')
                    self.logger.error(f'This is likely due to the same symbol defined multiple times')
                    self.symbols[i].node_embedding = np.zeros((cols, ), dtype=np.float64)

            self.logger.debug("Generating function ICFG embeddings")
            nbins = 48
            icfg_embed_mat, symb_l, null_l  = graph_embedding.build_graph_embeddings(self.symbols, nbins=nbins)
            for i, elem in enumerate(symb_l):
                self.symbols[elem].icfg_embedding = icfg_embed_mat[i, :]

            if len(icfg_embed_mat) > 0:
                ##if we have an example vector, set null vectors
                for elem in null_l:
                    self.symbols[elem].icfg_embedding = np.zeros((nbins*5,), np.int64)


        def analyse_identify_static(self):
            ##NB: need to analyse entry point first
            try: 
                entry_func   = self.symbol_mapper[self.entrypoint]

                if len(entry_func.asm) == 0:
                    #raise RuntimeError("Please analyse entrypoint before running analyse_identify_static")
                    self.logger.debug("No prior analysis of the entrypoint! Analysing...")
                    entry_func.analyse(self, r2_pipe_hdlr=self.r2_hdlr)

            except ValueError as e:
                self.logger.warning("Cannot find symbol at entry point!")
                return 

            if self.bin_format == 'elf' and self.os != "openbsd":
                # fails if OpenBSD ELF
                funcs = static_rules.identify_functions_from_glibc_entry(self, entry_func)
                self.logger.info("Found {} functon through static rules, applying found function names".format(len(funcs)))
                ##need to lookup symbol index
                for func_d in funcs:
                    vaddr       = func_d['vaddr']
                    name        = func_d['name']
                    real_name   = func_d['real_name']

                    for i, s in enumerate(self.symbols):
                        if s.vaddr == vaddr:
                            self.symbols[i].name = name
                            self.symbols[i].real_name = real_name

                ##adds 0 sized constructors and destructors as func symbols
                static_rules.identify_constructors_destructors_from_elf_header(self)
            ##update function mapping
            self._build_vaddr_to_func_name_tree()

        def analyse(self, exported_only=False, DATA_FLOW_ANALYSIS=True, SE_ANALYSIS=True, override=True):
            """
                Analyse a binary
                override=True, overrides previous analysis
            """
            self._analyse_init(exported_only=exported_only, override=override)

            if len(self.symbols) == 0:
                self.logger.warning(f"Error {self.path} has no symbols! If PE file, set binary.stripped = True and then re-run binary.analyse().")
                return

            ##resolve each function
            if self.linkage == 'dynamic':
                self.logger.info("Resolving all dynamically linked function prototypes")
                self.preload_function_prototype_from_db()

            ##limit symbols to filter ELF section ranges
            vex_const_filt = self._analyse_build_filt()

            if self.config.analysis.binary.ANALYSE_SYMBOLS:
                self.logger.debug("Analysing symbols!")
                self._analyse_symbols(vex_const_filt)
                self._analyse_add_callers()

            ##convert vaddrs in symbols CFG to names
            for i in tqdm.tqdm(range(len(self.symbols)), desc="Relabelling CFG"):
                self.relabel_symbols_cfg(i)

            ##disable for library functions
            if DATA_FLOW_ANALYSIS:
                see = SymbolicExecutionEngine(self.config, self, SYMB_SOLVER=SE_ANALYSIS)
                self._analyse_advanced(see)
                self._analyse_tainted_function_flows()

            if self.config.analysis.binary.ANALYSE_CALLGRAPH:
                self._analyse_build_callgraph()

            # performance optimization for closure computations
            # first, sort reverse topologically, then cache 0 deps results
            # u -> v is sorted so u comes first. We want leave nodes first
            try:
                self.transitive_closure_cache   = {}
                #no loops or online updates 
                g   = reversed(list(nx.topological_sort(self.callgraph)))
            except:
                #sort by smallest number of callees
                l   = list(map(lambda x: [x.real_name, x.callees], self.symbols))
                L   = sorted(l, key=lambda x: len(x[1]))
                nL, cL  = zip(*L)
                g = iter(nL)

            symb_ids_to_process    = set(range(len(self.symbols)))
            with tqdm.trange(len(self.symbols), desc='Computing transitive closure') as t:
                while len(symb_ids_to_process) > 0:
                    try:
                        # first take callgraph nodes from topological sort
                        symb_index      = None
                        real_name       = next(g)
                        symb_indexes    = set(self.get_symbol_index(real_name)) & symb_ids_to_process
                        if len(symb_indexes) > 0:
                            symb_index  = list(symb_indexes)[0]

                    except StopIteration as err:
                        symb_index  = sample(symb_ids_to_process, 1)[0]
                        real_name   = self.symbols[symb_index].real_name

                    finally:
                        self.logger.debug(f'Computing transitive closure for symbol: {real_name}, at index {str(symb_index)}')
                        ##dynamically imported, skip
                        if isinstance(symb_index, type(None)):
                            continue

                        t.set_postfix(name=real_name.ljust(30)[-30:], index=symb_index)

                        self.symbols[symb_index].closure = list(self.compute_transitive_closure(self.symbols[symb_index].real_name))
                        self.symbols[symb_index].tainted_args_closure = self.compute_transitive_tainted_flow_closure(self.symbols[symb_index])

                        #save to cache
                        self.transitive_closure_cache[real_name]    =  copy.copy(set(self.symbols[symb_index].closure))
                        
                        #remove index from processing set
                        symb_ids_to_process.remove(symb_index)
                        t.update(1)
                t.close()


        def analyse_fast(self, library=False):
            self._analyse_init(exported_only=library)

            vex_const_filt = self._analyse_build_filt()

            if self.config.analysis.binary.ANALYSE_SYMBOLS:
                self.logger.debug("Analysing symbols!")
                self._analyse_symbols(vex_const_filt)
                self._analyse_add_callers()

            ##convert vaddrs in symbols CFG to names
            for i in tqdm.tqdm(range(len(self.symbols)), desc="Relabelling CFG"):
                self.relabel_symbols_cfg(i)

            see = SymbolicExecutionEngine(self.config, self)
            see.solver = claripy.solvers.SolverConcrete()
            with tqdm.trange(len(self.symbols), desc='Analysis') as t:
                for i in t:
                    t.set_postfix_str(self.symbols[i].name.ljust(30)[:30])

                    lva = LiveVariableAnalysis(self.config, self.symbols[i])

                    func_args, heap_args, tls_args, live_locals, local_stack_bytes, num_locals, resolved = lva.analyse(see)
                    self.symbols[i].arguments         = list(func_args)
                    self.symbols[i].heap_arguments    = list(heap_args)
                    self.symbols[i].tls               = list(tls_args)
                    self.symbols[i].local_stack_bytes = local_stack_bytes
                    self.symbols[i].locals            = num_locals
                    self.symbols[i].num_args          = len(func_args)

            func_prototypes = list(map(lambda x: { 
                'name': x.name, 'args': x.arguments, 'heap_args': x.heap_arguments, 'real_name': x.real_name, 'tls_args': x.tls,
                    'local_stack_bytes': x.local_stack_bytes, 'num_args': x.num_args, 'path': self.path, 'bin_name': self.name, 'ret': 'unkown' 
                    }, self.symbols))
            return func_prototypes

        def analyse_symbol_fast(self, symbol_name):
            #if not self.r2_hdlr:
            #    self.r2_hdlr = r2pipe.open(self.path, ["-2"])

            if len(self.symbols) == 0:
                self.logger.debug("Extracting symbols...")
                self.r2_extract_symbols()

                ##add other imports for xrefs, plt funcs
                if self.linkage == "dynamic":
                   self.r2_add_dyn_imports()
                   self.r2_add_dyn_import_objects()

                self.logger.debug("{} :: Found {} symbols...".format( __file__, len(self.symbols) ))
                self.logger.debug("{} :: Found {} imported funcs...".format( __file__, len(self.dyn_imports) ))
                self._build_vaddr_to_func_name_tree()
                self._build_vaddr_to_data_name_tree()

                self.logger.debug("{} :: Analysing symbols!".format(__file__))

                if len(self.symbols) == 0:
                    self.logger.warn("Error {} has no symbols!".format(self.path))
                    return

            s = self.get_symbol(symbol_name)
            s.analyse(self, r2_pipe_hdlr=self.r2_hdlr)
            see = SymbolicExecutionEngine(self.config, self)

            print("Analysing", s.name)
            lva = LiveVariableAnalysis(self.config, s)
            func_args, heap_args, tls_args, live_locals, local_stack_bytes, num_locals, resolved = lva.analyse(see)

            s.arguments         = list(func_args)
            s.heap_arguments    = list(heap_args)
            s.tls               = list(tls_args)
            s.locals            = num_locals
            s.num_args          = len(func_args)
            s.live_locals       = live_locals
            return s


        def compute_transitive_closure(self, real_name, deps=None):
            """
                Compute reachable functions called from this function
                Probably have circular dependencies, tracks dependencies 
                so we don't stack overflow
            """
            if not deps:
                deps = set([])

            for s in self.get_all_symbols(real_name):
                #check if we have already added this symbol's callees
                if s.real_name in deps:
                    continue

                deps.add(s.real_name)
                for callee in s.callees:
                    if callee not in deps:
                        ##get result from whole cache (i.e. no deps)
                        if callee in self.transitive_closure_cache:
                            deps |= self.transitive_closure_cache[callee]
                        else:
                            #deps |= self.compute_transitive_closure(callee, deps=copy.copy(deps))
                            deps |= self.compute_transitive_closure(callee, deps=deps)
                    deps.add(callee)

            return deps

        def compute_transitive_tainted_flow_closure(self, symbol: Symbol):
            """
                Compute the transitive closure of tainted flows.

                Given the tainted flows for the current function, track 
                all tainted flows from each argument to other locations in the binary.

                tainted_args = {
                    'rsi' : { 'funcA' : (rsi, rdi), ...},
                    'rdi' : { 'mem_0x123' },
                    ...
                    ...
                }
                This reads: when rsi to the current function is tainted, rsi and rdi to funcA are also tainted.
            """
            tainted_args_closure    = {}
            for tainted_input_argument in symbol.arguments:
                ## {'rsi' : { funcA : [1, 2, 3] } }
                flows   = self._rec_track_tainted_flow(copy.deepcopy(symbol.tainted_args[tainted_input_argument]))
                tainted_args_closure[tainted_input_argument] = flows
            return tainted_args_closure


        def _rec_track_tainted_flow(self, flows: dict, deps=set([])):
            """
                Recursively track flows
            """
            for func_name, func_args in list(flows.items()):
                #skip recursing into FUNC_RET, not a symbol
                if func_name == '__FUNC_RET__':
                    continue

                callee_s        = self.get_symbol(func_name)
                if not callee_s:
                    self.logger.warning("Cannot resolve symbol: {}".format(func_name))
                    continue

                if not isinstance(callee_s, Symbol):
                    ##dynamically imported function
                    self.logger.debug("Skipping dynamically imported tainted flows")
                    continue

                t_callee_flows  = callee_s.tainted_args
                for caller_arg in list(func_args):
                    ##skip where caller arg not not relate to tainted flow in callee
                    if caller_arg not in t_callee_flows:
                        continue

                    for callee_func_name, callee_func_args in list(t_callee_flows[caller_arg].items()):
                        ##rename tainted function returns
                        if callee_func_name == '__FUNC_RET__':
                            callee_func_name = func_name + "::" + "__FUNC_RET__"

                        if callee_func_name in flows:
                            flows[callee_func_name] |= callee_func_args
                        else:
                            flows[callee_func_name] = callee_func_args

                        deps_key    = callee_s.real_name + "::" + caller_arg
                        if deps_key not in deps:
                            deps.add(deps_key)
                            child_flows = self._rec_track_tainted_flow(copy.deepcopy(t_callee_flows[caller_arg]), deps=deps )
                            if "__FUNC_RET__" in child_flows:
                                del child_flows['__FUNC_RET__']
                            flows.update( child_flows )

            return flows
                        
        def get_tainted_function_flows(self, vaddr: int):
            try:
                symbol  = self.symbol_mapper[vaddr]
            except ValueError:
                self.logger.warning(f"Cannot resolve tainted function flows to vaddr: {vaddr}")
                return dict()

            if hasattr(symbol, 'tainted_args'):
                return symbol.tainted_args

            #TODO: Implement database lookup of tainted flows from argument to x
            self.logger.warning("DB lookup of tainted flows for dynamically imported functions not implemented! Missing tainted function flows for symbol: {}".format(symbol['real_name']))
            return dict()

        def taint_func_flows(self):
            sse = SymbolicExecutionEngine(self.config, self)

            for i, s in enumerate(self.symbols):
                sse.clear_machine_state()
                analysis = sse.taint_and_track_symb(s)
                self.symbols[i].sse = analysis

                self.logger.info("Tainted {} at index {}".format(s.real_name, i))


        def taint_func_args_flows(self, s):
            """
                Need knowledge of all functions in binary to calculate flows, live 
                variables to functions
                :param s: Symbol
            """
            global_flows = set([])
            global_tracked = set([])
            print("Tainting symbol {}".format(s.name))
            for arg in s.vex['arguments']:
                flows, tainted, tracked = self.taint_func_arg_flows(s, arg)
                ##merge dicts
                #global_flows = { **global_flows, **flows }
                global_flows = global_flows.union( flows )
                global_tracked = global_tracked.union( tracked )

                print("\t\tFinal tainted: {}".format(tainted))
                print("\t\tFinal flows: {}".format(flows))
            print("Global flows: {}".format(global_flows))
            return global_flows, global_tracked

        def get_symbol(self, value, key='real_name'):
            a = list(filter(lambda x: getattr(x, key) == value, self.symbols))
            if len(a) > 1:
                self.logger.error('Multiple symbols with property `{}` {}'.format(key, value))
                return a[0]
            elif len(a) == 1:
                return a[0]

            ##check dynamic imports
            a = list(filter(lambda x: key in x and x[key] == value, self.dyn_imports))
            if len(a) > 1:
                self.logger.error('Multiple dynamic symbols with property `{}` {}'.format(key, value))
                return a[0]
            elif len(a) == 1:
                return a[0]

            self.logger.warning("Could not find symbol for key=`{}` and value=`{}`".format(key, value))
            return None
		
        def get_symbol_desc(self, kv_pairs:dict):
            """
                Return list of all valid symbols with descriptions
            """
            return list(filter(lambda x, kv_pairs=kv_pairs: all(getattr(x, key) == value for key, value in kv_pairs.items()), self.symbols))

        def get_all_symbols(self, value, key='real_name'):
            for x in self.symbols:
                if getattr(x, key) == value:
                    yield x

        def get_symbol_index(self, value, key='real_name'):
            """
                Return index of matching symbol in Binary.symbols
            """
            for i in range(len(self.symbols)):
                if getattr(self.symbols[i], key) == value:
                    yield i

        def taint_func_arg_flows(self, s, arg):
            flows   = []
            global_flows = []

            if not isinstance(arg, set):
                self.logger.error("Error! Need to pass an iterable set of arguments to taint. Not {}".format(arg))
                raise RuntimeError("Error! Need to pass an iterable set of arguments to taint. Not {}".format(arg))

            #self.logger.debug("\tTainting func arg: {}".format(arg))
            #tainted = set([ arg ]) ##live registers - killed registers
            self.logger.debug("\tTainting: {}".format(arg))
            tainted = copy.deepcopy(arg)

            #print("Symbol has {} basic blocks".format(len(s.bbs)))

            #mimic stack
            rsp = claripy.BVV(0x10000, 64)
            rbp = rsp + claripy.BVV(0x008, 64)

            ##fake special registers
            #cs = claripy.BVS('cs', 64)
            #ds = claripy.BVS('ds', 64)
            #fs = claripy.BVS('fs', 64)
            #gs = claripy.BVS('gs', 64)
            #ss = claripy.BVS('ss', 64)
            #es = claripy.BVS('es', 64)

            ##Fake all registers because some functions do random shit
            ##They don't stick to calling convention

            cc_op = claripy.BVS('cc_op', 64)
            cc_dep1 = claripy.BVS('cc_dep1', 64)
            cc_dep2 = claripy.BVS('cc_dep2', 64)
            cc_ndep = claripy.BVS('cc_ndep', 64)

            sseround = claripy.BVS('sseround', 64)
            fsc3210 = claripy.BVS('fsc3210', 64)
            fpround = claripy.BVS('fpround', 64)
            ftop = claripy.BVS('ftop', 64)

            nraddr = claripy.BVS('nraddr', 64)
            dflag = claripy.BVS('dflag', 64)
            acflag = claripy.BVS('acflag', 64)
            idflag = claripy.BVS('idflag', 64)
            emnote = claripy.BVS('emnote', 64)
            cmstart = claripy.BVS('cmstart', 64)
            cmlen = claripy.BVS('cmlen', 64)
            ip_at_syscall = claripy.BVS('ip_at_syscall', 64)


            tracked = { 
                #'rsp' : rsp, 'rbp' : rbp, 'fs' : fs, 'gs': gs, 'ds': ds, 
                #'cs' : cs, 'ss' : ss, 'es' : es,
                ##add vex special regs
                'cc_ndep': cc_ndep, 'cc_op': cc_op, 'cc_dep1': cc_dep1, 'cc_dep2' : cc_dep2,
                'ftop': ftop, 'fpround': fpround, 'fsc3210': fsc3210, 'sseround': sseround,
                'd': dflag, 'id': idflag, 'ac': acflag, 'emnote': emnote, 'cmstart': cmstart,
                'cmlen': cmlen, 'ip_at_syscall': ip_at_syscall, 'nraddr': nraddr
            }

            for reg in ArchAMD64.register_list:
                tracked[ reg.name ] = claripy.BVS(reg.name, reg.size*8)
                for reg_name, start, size in reg.subregisters:
                    tracked[ reg_name ] = claripy.BVS(reg_name, size*8)

            #stack should be created symbolically, reads are made symbolic
            for i in range(8):
                #top_name = 'fptop' + str(i)
                tag_name = 'fptag' + str(i)
                #tracked[ top_name ] = claripy.BVS(top_name, 8)
                tracked[ tag_name ] = claripy.BVS(tag_name, 64)

            for bb in s.bbs:
                #bb.irsb.pp()
                if not isinstance(bb, BasicBlock):
                    print("Error! bb is not a baisc block")

                _flows, _tainted, _tracked = bb.taint_argument(tainted=tainted, tracked=tracked)
                flows += _flows

                ##only taint named registers iter-basicblocks
                ## tainted == live registers from a basic block
                tainted = set(filter(lambda x: isinstance(x, str), _tainted))
                ##maintain, register, memory prefixed with 'm_'.
                ##throw away temporary variables
                tracked = dict(filter(lambda x: isinstance(x[0], str), _tracked.items()))


            ##convert numeric flows into named flows and check live func args
            for flow in flows:
                start_vaddr, end_vaddr, tainted_reg_args = flow

                start_name  = s.name

                #handle return flows
                if end_vaddr == 'ret':
                        taint_start = (s.name, frozenset(arg))
                        taint_end   = ('ret', tainted_reg_args)

                        #store flow
                        global_flows.append(( taint_start,taint_end ))
                        continue

                elif isinstance(end_vaddr, str):
                    assert(end_vaddr[0] == 't')
                    ##jump is computed, use simuvex on function to analyse jumps


                #end_name    = symb_vaddr[end_vaddr]
                end_names = list( self.vaddr_to_real_name_tree.at( end_vaddr ) )
                if(len(end_names) != 1):
                    self.logger.error("ERROR, call reference not found!! {} :: {} -> {}".format(s.name, hex(start_vaddr), hex(end_vaddr)))
                    #raise Exception("Cannot determine function reference!")
                    #Sometimes this happens, such as null functions ???
                    #Functions calls a function which simply rets
                    #https://reverseengineering.stackexchange.com/questions/2420/what-are-nullsub-functions-in-ida
                    continue

                end_name = end_names[0].data

                ##skips flows that are boring jumps within function
                ##checks if start of symbol t ohandle recursive jumps
                if end_name == s.name and end_vaddr != s.vaddr:
                    continue

                ##lookup symbol arguments
                static_matches  = list(filter(lambda x, end_name=end_name: x.name == end_name, self.symbols))
                for match in static_matches:
                    ##default num_args for unknown functions, imports ect
                    j = self.get_symbol(match.real_name, real_name=True)
                    if not j:
                        raise RuntimeError("Error getting symbol: {}".format(match))
                    if 'arguments' in j.vex:
                        num_args = len(j.vex['arguments'])

                    for i, reg in enumerate( [ 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9' ]):
                        ##function args is tainted but not used by callee function
                        if num_args <= i:
                            break

                        if reg in tainted_reg_args:
                            taint_start = (s.name, frozenset(arg))
                            taint_end   = (end_name, reg)

                            #store flow
                            global_flows.append(( taint_start,taint_end ))
                        else:
                            #print("Not a valid flow...")
                            pass


                dyn_matches     = list(filter(lambda x, end_name=end_name: x['name'] == end_name, self.dyn_imports))
                """
                    NB: The number of matches can be greater than 0, add flows for each match.
                """
                for match in dyn_matches:
                    self.logger.debug("Resolving dynamic function {} ({}) from libs {}".format(match['real_name'], end_name, self.libs))
                    #get real symbol name
                    #real_name = list( self.vaddr_to_real_name_tree.at( end_vaddr ) )[0].data
                    real_name = match['real_name']
                    lib_func = self.resolve_function_prototype_from_db(real_name)
                    self.logger.debug("Resolved!")

                    #for i, reg in enumerate( [ 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9' ]):
                    for farg in lib_func['arguments']:
                        if farg in tainted_reg_args:
                            taint_start = (s.name, frozenset(arg))
                            taint_end   = (end_name, farg)

                            #store flow
                            global_flows.append(( taint_start,taint_end ))
                        else:
                            #print("Not a valid flow...")
                            pass

            #return set(global_flows), tainted, tracked
            return global_flows, tainted, tracked

        #cache all name lookups
        #cannot hash self (Binary)
        #@functools.lru_cache(maxsize=None)
        @cached(cache={}, key=lambda self, name, real_name: hashkey(name, real_name))
        def get_func_args(self, name, real_name):
            """
                Get the number of function argument for a symbol name. 
                static or dynamically linked
            """
            ##lookup symbol arguments
            if real_name:
                static_matches  = list(filter(lambda x, name=name: x.real_name == name, self.symbols))
            else:
                static_matches  = list(filter(lambda x, name=name: x.name == name, self.symbols))

            for symbol in static_matches:
                return symbol.arguments

            attr = 'real_name' if real_name else 'name'
            dyn_matches = list(filter(lambda x, name=name: x[attr] == name, self.dyn_imports))
            for match in dyn_matches:
                self.logger.debug("Resolving dynamic function {} ({}) from libs {}".format(match['real_name'], name, self.libs))
                #get real symbol name
                #real_name = list( self.vaddr_to_real_name_tree.at( end_vaddr ) )[0].data
                real_name = match['real_name']
                if real_name in self.dyn_symbol_cache:
                    symbol = self.dyn_symbol_cache[real_name]
                    return symbol['arguments']

                self.logger.debug("Resolving dynamic function {} ({}) from libs {} using database".format(match['real_name'], name, self.libs))
                lib_func = self.resolve_function_prototype_from_db(real_name)
                if not lib_func:
                    self.logger.error("Assuming 0 arguments for function: {}".format(real_name))
                    ###default to no arguments
                    lib_func = {
                        'real_name': real_name,
                        'name': name,
                        'arguments': [],
                        'num_args': 0
                    }
                #num_args = len(lib_func['params'])
                #x86_64_sysv_abi_arg_regs = [ 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9' ]
                #lib_func['arguments'] = set(x86_64_sysv_abi_arg_regs[:num_args])
                self.logger.debug("Resolved!")
                self.dyn_symbol_cache[real_name] = lib_func
                if not 'arguments' in lib_func:
                    print("Missing arguments")
                return lib_func['arguments']
            return None

class MissingLibrary(RuntimeError):
    def __init__(self, arg, libname):
        self.stderror = arg + libname
        self.args = {arg, libname}
        self.library = libname

class UnsupportedISA(RuntimeError):
    def __init__(self, binary):
        self.stderror = "Unsupported ISA {} for binary".format(binary.arch,
                binary.path)
        self.binary = binary

class UnsupportedLang(RuntimeError):
    def __init__(self, binary):
        self.stderror = "Unsupported language {} for binary".format(binary.lang,
                binary.path)
        self.binary = binary

class StrippedBinaryError(RuntimeError):
    def __init__(self, binary):
        self.stderror = "Refusing to analyse stripped binary {} ".format(binary.path)
        self.binary = binary

class FunctionTooLarge(RuntimeError):
    def __init__(self, binary, name, size):
        self.stderror   = "Refusing to analyse function {} of size {} from binary {} ".format(name, size, binary.path)
        self.binary     = binary
        self.name       = name
        self.size       = size

class BinaryTooLarge(RuntimeError):
    def __init__(self, binary):
        self.stderror   = "Refusing to analyse binary {} of size {}".format(binary.path, binary.size)
        self.binary     = binary

class BasicBlockMapper(Binary):
    """
        Class which takes a binary and implements indexing of basic blocks by vaddr
        binary.bbs[0x3654]
    """
    def __init__(self, b):
        self.binary = b

    def __getitem__(self, key):
        assert(isinstance(key, int))
        for interval in self.binary.vaddr_to_real_name_tree.at(key):
            s = self.binary.get_symbol(interval.data)
            if s:
                for e in filter(lambda x: x.vaddr == key, s.bbs):
                    return e
            return None 

class SymbolMapper(Binary):
    """
        Class which takes a binary and implements indexing of basic blocks by vaddr
        binary.bbs[0x3654]
    """
    def __init__(self, b):
        self.binary = b

    def __getitem__(self, key):
        """ find symbol in binary for key """

        if isinstance(key, int):
            for interval in self.binary.vaddr_to_real_name_tree.at(key):
                return self.binary.get_symbol(interval.data, key='real_name')

            raise ValueError(f"No symbol with vaddr {key}")
        elif isinstance(key, dict):
            # Return list of all valid symbols with descriptions
            return list(filter(lambda x, kv_pairs=kv_pairs: all(getattr(x, key) == value for key, value in kv_pairs.items()), self.binary.symbols))

        elif isinstance(key, str):
            return self.binary.get_symbol(key, key='real_name')

        raise TypeError(f"SymbolMapper[key]: key should be a virtual address, symbol name, or key:val dict")
