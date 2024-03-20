
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

#!/usr/bin/pyhton3
import copy
import random
import json
import os, sys, functools
import re
import r2pipe
import binascii
import subprocess
import pymongo
import pprint
import math
import hashlib
import lief
import re
import networkx as nx
import collections
from networkx.drawing import nx_agraph
from networkx.drawing.nx_pydot import write_dot
import pygraphviz
import logging
from intervaltree import Interval, IntervalTree
from threading import Thread, Lock
import IPython
import claripy
import tqdm
from joblib import Parallel, delayed
from multiprocessing import Pool
import claripy

from cachetools import cached
from cachetools.keys import hashkey

import context
from classes.config import Config
from classes.symbol import Symbol
from classes.symbex import SymbEx
from classes.dwarf import DwarfInfo
from classes.database import Database
from classes.basicblock import BasicBlock, NoNativeInstructionsError
from classes.basicblocksequence import BasicBlockSequence
from classes.basicblocksequence import LiveVariableAnalysis, ConstantPropagation, TaintPropagation
from classes.symbolic_execution_engine import SymbolicExecutionEngine
from classes.function_boundary_detection import FB
import classes.utils
import classes.static_rules
import classes.NLP
from archinfo.arch_amd64 import ArchAMD64


def par_analyse_symbol(symbol):
    """
    Py Multiprocess simple symbol analysis
    """
    symbol.analyse()
    return symbol


def par_advanced_symbol_analysis(_b, symbol):
    """
    Py Multiprocess advanced symbol analysis
    """
    config = Config()
    symbol.config = config
    see = SymbolicExecutionEngine(self.config, _b)
    print("Analysing", symbol.name)
    lva = LiveVariableAnalysis(config, symbol)
    tpa = TaintPropagation(config, symbol)
    live_args, live_heap, live_thread_local_storage, live_locals, local_stack_bytes, num_locals, resolved = lva.analyse(see)
    self.logger.info("Performing Taint Propagation with recovered function arguments and propagated constants")
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
                'memcpy' : { 'name' :'memcpy', 'arguments': [  'rsi', 'rdi', 'rdx' ] },
                'memset' : { 'name' :'memset', 'arguments': [  'rsi', 'rdi', 'rdx' ] },
                'setjmp' : { 'name' :'setjmp', 'arguments': [ 'rdi' ] }
        }

        #path argumnet is required
        def __init__(self, config, name="", size=-1, data=b'', symbols=[], objects=[],
                path="", optimisation=-1, compiler="", linkage="", stripped=-1,
                libs=[], must_resolve_libs=True,
                bbs=[], cfg=None, callgraph=None, arch="x86_64", 
                collection_name='', lang=''):

            classes.utils._desyl_init_class_(self, config)
            if not os.path.isfile(path):
                raise Exception("Error, path argument to binary ({}) is not a file!".format(path))

            self.logger.debug("Analysing {}...".format( path ))

            self.path = path
            self.name = name
            self.size = size
            self.libs = libs
            self.linkage = linkage
            self.symbols = symbols
            self.optimisation = optimisation
            self.linkage = linkage
            self.compiler = compiler
            self.data = data
            self.stripped = stripped
            self.bbs = bbs
            self.cfg = cfg
            self.arch = arch
            self.callgraph = callgraph
            self.collection_name = collection_name
            self.r2_hdlr = None
            self.lang = lang
            self.dyn_imports = []
            self.dyn_objects = []
            self.dyn_symbol_cache = {}
            self.sections = []
            self.objects = objects
            """
            Mapper objects allow for lookups based on vaddr
            binary.symbol_mapper[0x4432]
            """
            self.basicblock_mapper  = BasicBlockMapper(self)
            self.symbol_mapper      = SymbolMapper(self)

            self._infer_binary_params()

            if must_resolve_libs:
                ##load data sections
                self._r2_fill_sections_data()

                res, missing = self.resolve_linked_libraries()
                self.library_ids = res
                if missing:
                    raise MissingLibrary("Cannot resolve all dynamically linked libraries. ", missing)
            
            self.header         = lief.parse(self.path)
            if not self.header:
                raise RuntimeError("Error parsing file header")
            self.entrypoint     = self.header.entrypoint

        def __getstate__(self):
            classes.utils._desyl_deinit_class_(self)
            if hasattr(self, 'r2_hdlr'):
                del self.r2_hdlr
            return self.__dict__

        def __setstate__(self, state):
            self.__dict__ = state
            classes.utils._desyl_init_class_(self, Config())

        def __del__(self):
            if 'r2_hdlr' in self.__dict__:
                try:
                    if self.r2_hdlr:
                        self.r2_hdlr.quit()
                except Exception as e:
                    self.logger.error(e)

        #create Symbol from JSON
        @staticmethod
        def fromJSON(j):
            return Binary(name = j['name'],
                    path =  j['path'],
                    size =  j['size'],
                    libs =  j['libs'],
                    linkage = j['linkage'],
                    symbols =  j['symbols'],
                    optimisation =  j['optimisation'],
                    compiler =  j['compiler'],
                    data =  binascii.unhexlify( j['data'] ),
                    stripped =  j['stripped'],
                    arch = j['arch'],
                    collection_name = j['collection_name']
                    )

        @staticmethod
        def fromDatabase(db, path, collection_name):
            #symbols = Binary.get_symbols_from_db(db, path, collection_name)
            symbols = db.get_symbols_from_binary(path, collection_name)

            assert( len(symbols) > 0 )

            inconsistent_linkage = functools.reduce( (lambda x, y: x or y.linkage != symbols[0].linkage), symbols, False)
            inconsistent_optimisation = functools.reduce( (lambda x,y: x or y.optimisation != symbols[0].optimisation), symbols, False)
            inconsistent_compiler = functools.reduce( (lambda x,y: x or y.compiler != symbols[0].compiler), symbols, False)
            inconsistent_arch = functools.reduce( (lambda x,y: x or y.arch != symbols[0].arch), symbols, False)

            if not inconsistent_linkage and not inconsistent_compiler and not inconsistent_optimisation:
                return Binary(name = os.path.basename(path),
                        path =  path,
                        linkage = symbols[0].linkage,
                        symbols =  symbols,
                        optimisation =  symbols[0].optimisation,
                        compiler =  symbols[0].compiler,
                        arch =  symbols[0].arch,
                        collection_name = collection_name
                        )

            self.logger.error("Error inconsistent symbols found for binary!")
            assert(False)

        def clone(self):
            return copy.deepcopy(self)

        def __eq__(self, other):
            return self.data == other.data

        def to_json(self, verbose=False):
            df = self.to_dict(verbose=verbose)
            return json.dumps( df, sort_keys=True, indent=4)


        @staticmethod
        def caller_vaddr_lookup(db, path, vaddr):
            res = db.client.find_one({ 'path': path, 'vaddr': vaddr}, {'name':1})
            return res['name']


        #Binary data is printing as hex string! Nothing prepends string e.g. "0x"
        def __str__(self):
            return self.to_json()

        """
        def to_dict(self):
            assert( type( self.data ) == type(b'') )

            return {'name': self.name,
                    'size': self.size,
                    'data': binascii.hexlify( self.data ).decode('ascii'),
                    'symbols': self.symbols,
                    'stripped': self.stripped,
                    'compiler': self.compiler,
                    'optimisation': self.optimisation,
                    'path': self.path,
                    'linkage' : self.linkage,
                    'collection_name' : self.collection_name,
                    }

        """

        #save symbols to db
        def save_symbols_to_db(self, db):
            num_inserted = Symbol.save_to_db_many(self.symbols, db)
            self.config.logger.debug("Saved {} symbols to the database".format(num_inserted))

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

            ##special case of ld-inux
            if lib == "ld-linux-x86-64.so.2":
                return lib

            lib_re  = r'^lib(.+?)(?:-[0-9\.]+)*\.so.*$'
            if self.bintype == 'pe':
                lib_re  = r'^(.*)\.dll$'

            m = re.match(lib_re, lib)
            if not m:
                self.logger.error("{}, {}".format(m, lib))
                self.logger.error("Error parsing dynamically linked library name!")
                raise RuntimeError("Error parsing dynamically linked library name!")

            if self.bintype == 'pe':
                return m.group(1)

            return 'lib' + re.escape(m.group(1))

        def resolve_linked_libraries(self):
            """
                Check that we have a version of the linked libraries required
                to run binary in the database
                :return: (Bool, Missing lib name)
            """
            psql_db = classes.database.PostgresDB(self.config)
            psql_db.connect()
            curr = psql_db.conn.cursor()
            library_ids = set([])
            for lib in self.libs:
                ##clean lib name
                lib_name = self._clean_lib_name(lib)
                self.logger.info("Dynamically linked library: {} -> {}".format(lib, lib_name))
                lib_match_re = r'^' + lib_name + r'[^a-zA-Z]*\.so.*'

                lib_ids = psql_db.resolve_library(curr, lib_match_re)
                if not lib_ids:
                    ##cannot resolve
                    return False, lib_name
                library_ids |= lib_ids
            return library_ids, None

        def resolve_function_prototype_from_debug_info(self, real_name):
            nlp = classes.NLP.NLP(self.config)
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
                        IPython.embed()
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
                            IPython.embed()
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

            nlp = classes.NLP.NLP(self.config)
            names = set(map(lambda x: nlp.strip_library_decorations(x['real_name']), self.dyn_imports))

            names -= set(Binary.GLOBAL_KNOWN_PROTOTYPES.keys())
            libs = list(map(lambda x: self._clean_lib_name(x), self.libs))

            db = classes.database.PostgresDB(self.config)
            db.connect()
            curr    = db.conn.cursor()
            for name in tqdm.tqdm(names, desc='Resolving dynamically linked function prototypes'):
                proto = db.resolve_dynamic_function(curr, list(self.library_ids), name)
                if not proto:
                    self.logger.error("Failed to resolve {} from library {}".format(name, libs))

                    if name[-2:] in ("64", "32"):
                        proto = db.resolve_dynamic_function(curr, list(self.library_ids), name[:-2])
                        if proto:
                            self.logger.error("Using function prototype for {}".format(name[:-2]))
                            Binary.GLOBAL_KNOWN_PROTOTYPES[ name ] = proto
                            continue


                    self.logger.error("Assuming no arguments")
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

            nlp = classes.NLP.NLP(self.config)
            name = nlp.strip_library_decorations(real_name)
            
            if real_name in Binary.GLOBAL_KNOWN_PROTOTYPES:
                return Binary.GLOBAL_KNOWN_PROTOTYPES[ real_name ]
            if name in Binary.GLOBAL_KNOWN_PROTOTYPES:
                return Binary.GLOBAL_KNOWN_PROTOTYPES[ name ]

            libs = list(map(lambda x: self._clean_lib_name(x), self.libs))

            #name_re = '(^|[^a-zA-Z]+|_+[a-zA-Z]+_+){}'.format(name)
            name_re = name

            db = classes.database.PostgresDB(self.config)
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
            raise RuntimeError("Failed to resolve {} from library {}".format(real_name, libs))

        def relabel_symbols_cfg(self, symb_index):
            """
                Relable nodes in CFG from vaddrs to full names '+' vaddrs
            """
            for node in list(self.symbols[symb_index].cfg.nodes()):
                if not isinstance(node, int):
                    continue
                vaddr = int(node)
                locs = self.vaddr_to_name_tree.at( vaddr )
                if len(locs) == 0:
                    self.logger.warning("Unknown call/jump to location - {} in {} (parsing vaddrs in CFG)".format(
                        node, self.symbols[symb_index].real_name))
                    classes.utils.nx_set_node_property( self.symbols[symb_index].cfg, node, 'label', "__DESYL_FUNC_UNKNOWN")
                    continue

                for dest in locs:
                    label = dest.data + "+" + hex( vaddr - dest.begin )

                    if hasattr(self.symbols[symb_index].cfg[node], 'label'):
                        ##try find alt label names
                        for i in range(2, 10):
                            if not hasattr(self.symbols[symb_index].cfg[node], 'label_'+ str(i)):
                                classes.utils.nx_set_node_property( self.symbols[symb_index].cfg, node, 'label_'+str(i), label)
                                break
                    else:
                        classes.utils.nx_set_node_property( self.symbols[symb_index].cfg, node, 'label', label)


        def _build_vaddr_to_func_name_tree(self):
            """
                Map virtual address ranges to function symbols in binary
            """
            self.vaddr_to_name_tree = IntervalTree()
            self.vaddr_to_real_name_tree = IntervalTree()
            count = 0
            self.logger.debug("[+] Building interval tree of vaddresses to function names")
            for s in self.symbols:
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
            self.vaddr_to_data_name_tree = IntervalTree()
            for dr in self.objects:
                name    = dr['name']
                vaddr   = dr['vaddr']
                size    = dr['size']
                ### cannot have 0 range interval
                if size > 0:
                    self.vaddr_to_data_name_tree.addi( vaddr, vaddr + size, name )
                else:
                    self.vaddr_to_data_name_tree.addi( vaddr, vaddr + 1, name )

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
                    start           = section['paddr']
                    size            = section['size']
                    end             = start + size

                    if start == 0:
                        ##ignore this section
                        continue

                    if size <= 0:
                        continue

                    contents = self.r2_read_bytes(start, size)
                    self.sections.append( (name, start, end, size, contents) )

        def r2_read_bytes(self, vaddr, size_in_bytes):
            """
                Read bytes from binary at vaddr
            """
            if size_in_bytes <= 0:
                return bytes()
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
                    tdata   = bytes(json.loads(self.r2_hdlr.cmd('pxj {} @ {}'.format(chunk_size, vaddr + (i*chunk_size)))))
                    assert(len(tdata) == chunk_size)
                    data    += tdata
                assert(len(data) == size_in_bytes)
                return data
            data    = bytes(json.loads(self.r2_hdlr.cmd('pxj {} @ {}'.format(size_in_bytes, vaddr))))
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
            if self.size > 1024 * 1024 * 100:
                raise BinaryTooLarge(self)

            if not self.r2_hdlr:
                self.r2_hdlr = r2pipe.open(self.path, ["-2"])

            info = self.r2_hdlr.cmdj('iIj')
            self.stripped   = info['stripped']
            self.linkage    = 'static' if info['static'] else 'dynamic'
            self.compiler   = info['compiler'] if 'compiler' in info else 'UNKNOWN'
            self.arch       = info['arch'] + '_' + str(info['bits'])
            self.lang       = info['lang'] if 'lang' in info else 'UNKNOWN'
            self.os         = info['os']
            self.bintype    = info['bintype']
            self.bin_class  = info['class']

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


        #Extract symbols after performing analysis on binary
        def r2_extract_symbols(self, exported_only=False):
            """
            Extract FUNC symbols using the r2 API
            Use exported_only=True to limit binding of symbols to GLOBAL or WEAK
            """
            self.symbols = []
            nlp = classes.NLP.NLP(self.config)
            if not self.r2_hdlr:
                self.r2_hdlr = r2pipe.open(self.path, ["-2"])

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

            for symb in func_symbols:
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
                        arch            = self.arch)

                self.logger.debug("{:<40}->{:>40}".format(symb['name'], s.name))
                self.symbols.append(s)

        def add_symbol_from_boundaries(self, f_boundaries):
            """
            Add symbols from an iterable set of function boundaries
            f_boundaries: [ (vaddr:int, size:int) ]
            """
            self.symbols = []
            for vaddr, size in f_boundaries:
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

                self.logger.debug("{:<40}->{:>40}".format(s.real_name, s.name))
                self.symbols.append(s)

        def r2_extract_lib_funcs(self):
            """
                Extracts all functions in a .so file with paramateres, return, and locals
            """
            funcs = []
            nlp = classes.NLP.NLP(self.config)
            if not self.r2_hdlr:
                self.r2_hdlr = r2pipe.open(self.path, ["-2"])

            self.logger.debug("Starting r2 advanced analysis")
            self.r2_hdlr.cmdj("aaaa")
            funcs = self.r2_hdlr.cmdj("afllj")
            IPython.embed()

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
                for caller in symbol.callers:
                    callgraph.add_edge( caller, symbol.name )
                for callee in symbol.callees:
                    callgraph.add_edge( symbol.name, callee )
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
            r_symbols       = json.loads( self.r2_hdlr.cmd( "isj" ) )
            obj_symbols     = list(filter(lambda x: x['type'] == "OBJ", r_symbols))
            for s in obj_symbols:
                obj = {
                    'name'  : s['realname'],
                    'vaddr' : s['vaddr'], 
                    'size'  : s['size'],
                    'data'  : self.r2_read_bytes(s['vaddr'], s['size'])
                }
                self.objects.append(obj)

        def r2_add_dyn_import_objects(self):
            r_imports   = json.loads(self.r2_hdlr.cmd("iij"))
            r_imp_objs  = filter(lambda x: x['type'] == "OBJECT", r_imports)
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
            """
            ##below is a hack because r2 is crap
            ##the address of relocated objects is available with the ir command but not the type of object
            ##the type is only avaliable with ii but the relocated address is all 0x0
            self.dyn_imports = []

            nlp = classes.NLP.NLP(self.config)
            #radare2 API keeps changing!!!!!! ir, ii is buggy
            #combine 2 lists to get both relocated address and func types
            r_imports = json.loads( self.r2_hdlr.cmd("iij") )
            r_imp_funcs = filter( lambda x: x['type'] == "FUNC", r_imports )
            ri = list(map(lambda x: 
                {
                    'name'  : nlp.strip_library_decorations( x['name'] ), 
                    'real_name'  : nlp.strip_r2_decorations( x['name'] ), 
                    'vaddr' : x['plt'],
                    'size' : 6
                }
            , r_imp_funcs ))

            """
                If address of import is 0, check relocation table
            """
            relocations = json.loads( self.r2_hdlr.cmd("irj") )
            reloc_funcs = filter( lambda x: 'name' in x and 'vaddr' in x, relocations )
            relocs = dict(map(lambda x:
                            [ nlp.strip_library_decorations( x['name'] ), x['vaddr'] ]
                            , reloc_funcs ))

            for f in ri:
                if f['vaddr'] == 0:
                    ##lookup in relocation table
                    if f['name'] in relocs:
                        f['vaddr'] = relocs[f['name']]
                        self.dyn_imports.append(f)
                        continue
                    #raise RuntimeError("Import has vaddr of 0x0000 and we cannot find it in the relocation table " + str(f['name']) + " :: " + str(f['vaddr']))
                    self.logger.error("Import has vaddr of 0x0000 and we cannot find it in the relocation table " + str(f['name']) + " :: " + str(f['vaddr']))
                self.dyn_imports.append(f)

        def _analyse_init(self, exported_only=False):
            """
                Extarct functions and data, build internal data structures
            """
            sys.setrecursionlimit(3500)
            if not hasattr(self, 'r2_hdlr') or not self.r2_hdlr:
                self.r2_hdlr = r2pipe.open(self.path, ["-2"])

            self.logger.debug("Extracting symbols...")
            """
                Stripped libarraies still contain dynamic symbolic information. Th ebinary is still considered
                stripped.
            """
            if self.stripped and not exported_only:
                self.logger.info("{} is stripped, extracting function boundaries!".format(self.path))
                fb = FB()
                f_boundaries = fb.ghidra_extract_function_boundaries(self.path, self.linkage=="dynamic")
                self.add_symbol_from_boundaries(f_boundaries)
            else:
                #self.dwarf = DwarfInfo(self)
                self.r2_extract_symbols(exported_only=exported_only)

            self.r2_add_objects()

            ##add other imports for xrefs, plt funcs
            if self.linkage == "dynamic":
               self.r2_add_dyn_imports()
               self.r2_add_dyn_import_objects()

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
                            m=self.vaddr_to_name_tree: m.at(x),
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
                    self.symbols[sym_index].data_refs = data_refs

        def _analyse_add_callers(self):
            ##build callers after resolving all callees
            ##build name to index for fast lookup
            symbol_index_cache = dict(map(lambda x: [x[1].name, x[0]], enumerate(self.symbols)))
            for s in tqdm.tqdm(self.symbols, desc="Building Callers"):
                for callee in s.callees:
                    if callee in symbol_index_cache:
                        self.symbols[ symbol_index_cache[callee] ].callers.add( s.name )

        def _analyse_advanced(self, see:SymbolicExecutionEngine):
            """
                Analyse function with symbolic execution engine of choice
            """
            for i in tqdm.tqdm(range(len(self.symbols)), desc="Analysing symbols with symbolic memory model"):
                self.logger.debug("Analysing {}".format(self.symbols[i].name))

                lva = LiveVariableAnalysis(self.config, self.symbols[i])
                tpa = TaintPropagation(self.config, self.symbols[i])
                #func_args, heap_args, stack_vars, resolved, thread_local_storage = lva.analyse(see)
                #live_args, live_heap, live_thread_local_storage, live_locals, local_stack_bytes, num_locals, resolved
                live_args, live_heap, live_thread_local_storage, live_locals, local_stack_bytes, num_locals, resolved = lva.analyse(see)
                self.logger.info("Performing Taint Propagation with recovered function arguments and propagated constants")
                flows = tpa.analyse(self, live_args, resolved=resolved)

                self.symbols[i].arguments         = list(live_args)
                self.symbols[i].heap_arguments    = list(live_heap)
                self.symbols[i].tls               = list(live_thread_local_storage)
                self.symbols[i].locals            = list(live_locals)
                self.symbols[i].local_stack_bytes= local_stack_bytes
                self.symbols[i].tainted_flows     = flows
                self.symbols[i].num_args          = len(live_args)

        def _analyse_tainted_function_flows(self):
            #need to reduce set of tainted variables in flows to 
            #that af function arguments for the corresponding function
            for i in tqdm.tqdm(range(len(self.symbols))):
                for j, flow in enumerate(self.symbols[i].tainted_flows):
                    func, args = flow
                    if func == "__FUNC_RET__":
                        self.symbols[i].tainted_flows[j] = (func, list(args & set(['rax', 'xmm0', 'ymm0'])))
                        continue

                    func_args = self.get_func_args(func, real_name=False)
                    args = set(args) & set(func_args)
                    self.symbols[i].tainted_flows[j] = (func, list(args))

                ##remove flows where no args are tainted
                self.symbols[i].tainted_flows = list(filter(lambda x: len(x[1]) > 0, self.symbols[i].tainted_flows))

        def _analyse_build_callgraph(self):
            """
                Build callgraph and control flow graph for binary
            """
            self.logger.debug("Building callgraph...")
            self.callgraph  = self.build_callgraph_from_symbols()
            self.cfg        = self.build_cfg_from_symbols()

        def analyse_identify_static(self):
            funcs = classes.static_rules.identify_functions_from_glibc_entry(self, self.symbol_mapper[self.entrypoint])
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

        def analyse(self, exported_only=False, SSE_ANALYSIS=False):
            """
                Analyse a binary
            """
            self._analyse_init(exported_only=exported_only)

            if len(self.symbols) == 0:
                self.logger.warning("Error {} has no symbols!".format(self.path))
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
            if SSE_ANALYSIS:
                see = SymbolicExecutionEngine(self.config, self)
                self._analyse_advanced(see)
                self._analyse_tainted_function_flows()

            for symb_index in tqdm.tqdm(range(len(self.symbols)), desc="Computing transitive closure for symbols"):
                #print("Computing transitive closure for", self.symbols[symb_index].name)
                self.symbols[symb_index].closure = list(self.compute_transitive_closure(self.symbols[symb_index].name, set([])))

            if self.config.analysis.binary.ANALYSE_CALLGRAPH:
                self._analyse_build_callgraph()


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
                    t.set_postfix(name=self.symbols[i].name.ljust(30)[-30:], binary=self.name.ljust(20)[-20:])

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
            if not self.r2_hdlr:
                self.r2_hdlr = r2pipe.open(self.path, ["-2"])

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

        def to_dict(self, verbose=False):
            assert(isinstance( self.symbols, list ))
            assert(isinstance( self.bbs, list ))
            assert(isinstance( self.cfg, nx.DiGraph ) or isinstance(self.cfg, type(None)))
            assert(isinstance( self.callgraph, nx.DiGraph ) or isinstance(self.callgraph, type(None)))
            assert(isinstance( self.size, int ))

            return {
                'path' : self.path,
                'name' : self.name,
                'size' : self.size,
                'linkage' : self.linkage,
                'symbols' : list(map(lambda x: x.name, self.symbols)),
                'optimisation' : self.optimisation,
                'linkage' : self.linkage,
                'compiler' : self.compiler,
                'stripped' : self.stripped,
                'bbs' : self.bbs,
                'cfg' : str( nx_agraph.to_agraph( self.cfg ) ) if isinstance(self.cfg, nx.DiGraph) else "",
                'callgraph' : str( nx_agraph.to_agraph( self.callgraph ) ) if isinstance(self.callgraph, nx.DiGraph) else ""
            }

        def save_to_db(self, db):
            """
                Saves binary to the database
                Saved in collection indicated by db
            """
            collection_name = db.collection_name + self.config.binary_collection_suffix
            b = self.to_dict()
            res = db[collection_name].insert_one( b )
            self._id = res.inserted_id
            return self._id

        def save_to_rdb(self, db):
            """
                Saves binary to a redis database
            """
            db.set_py_obj("binary:{}".format(self.path), self)

        """
            WARNING: Caching this is a bad idea. Returns an emtpy set for some symbols???
            it is fast enough not to be needed
        """
        #@cached(cache={}, key=lambda self, name, deps: hashkey(name))
        def compute_transitive_closure(self, name, deps):
            """
                Compute reachable functions called from this function
                Probably have circular dependencies, tracks dependencies 
                so we don't stack overflow
            """
            #s = self.get_symbol(name)
            for s in self.get_all_symbols(name):
                if not s or s.name in deps:
                    return set([])

                for callee in s.callees:
                    if callee not in deps:
                        deps.add(callee)
                        deps |= self.compute_transitive_closure(callee, deps)

            return deps

        def taint_func_flows(self):
            sse = SymbolicExecutionEngine(self.config, self)

            for i, s in tqdm.tqdm(enumerate(self.symbols), desc="Tainting func flows"):
                sse.clear_machine_state()
                #flows = sse.execute_function(s, s.vex['arguments'])
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

        def get_symbol(self, value, key='name'):
            a = list(filter(lambda x: getattr(x, key) == value, self.symbols))
            if len(a) > 1:
                self.logger.error('Multiple symbols with property `{}` {}'.format(key, value))
                return a[0]
            elif len(a) == 1:
                return a[0]
            return None

        def get_symbol_desc(self, kv_pairs):
            """
                Return list of all valid symbols with descriptions
            """
            return list(filter(lambda x, kv_pairs=kv_pairs: all(getattr(x, key) == value for key, value in kv_pairs), self.symbols))

        def get_all_symbols(self, value, key='name'):
            for x in self.symbols:
                if getattr(x, key) == value:
                    yield x

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

            #mimic stack
            rsp = claripy.BVV(0x10000, 64)
            rbp = rsp + claripy.BVV(0x008, 64)

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
                    IPython.embed()

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
                end_names = list( self.vaddr_to_name_tree.at( end_vaddr ) )
                if(len(end_names) != 1):
                    self.logger.error("ERROR, call reference not found!! {} :: {} -> {}".format(s.name, hex(start_vaddr), hex(end_vaddr)))
                    #IPython.embed()
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
                    IPython.embed()
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
        for interval in self.binary.vaddr_to_name_tree.at(key):
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
        assert(isinstance(key, int))
        for interval in self.binary.vaddr_to_name_tree.at(key):
            return self.binary.get_symbol(interval.data)

if __name__ == '__main__':
    print("Analysing binary", sys.argv[1])
    config  = classes.config.Config()
    b       = Binary(config, path=sys.argv[1], must_resolve_libs=False)

    #b.analyse()
    IPython.embed()
