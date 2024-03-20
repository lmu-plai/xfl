
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, Tristan Benoit, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

#!/usr/bin/pyhton3
import copy
import json
import hashlib
import tqdm
import numpy as np
import scipy as sp
import archinfo
from functools import reduce
import IPython
from config import Config
from basicblocksequence import BasicBlockSequence
import utils

class Symbol(BasicBlockSequence):

    def __init__(self, config, name="", real_name="", bin_name="", path="", optimisation=-1, 
            compiler="", type="", linkage="", _id=-1, sse={}, closure=[],
            arguments=[], heap_arguments=[], local_stack_bytes=0, tls_arguments=[], sha256=b'',
            tainted_args={}, tainted_args_closure={}, node_embedding=None, icfg_embedding=None,
            binding="UNKNOWN", num_args=-1, signature="", *args, **kwargs):
        """
        A Symbol represents a FUNC ELF SYMBOL. Wraps around a BasicBlockSequence
        class

        :param name: - the name of the symbol
        :param real_name: - the name of the symbol
        :param bin_name: - the binary this symbol belongs to.
        :param size: - the size of this symbol, and integer
        :param vaddr: - the virtual address of the symbol
        :param hash: SHA 256 hash of the binary data
        :param opcode_hash: SHA 256 hash of the ASM opcodes
        :param data: Binary data
        :param path: String path of the binary
        :param optimisation: Compiler optimisation level
        :param compiler: compiler used
        :param type: - infered/not
        :param linkage: From a static of dynamically linked binary
        :param vex: VEX information
        :param asm: List of ASM instructions
        :param opcodes: List of ASM OPCodes
        :param BBS: List of BasicBlocksSequences
        :param binding: ELF symbol binding
        :param arch: ISA of symbol
        :param cfg: IntraProcedural Control Flow Graph for symbol
        :param callers: List of callees - functions which the symbol calls
        :param callees: List of callers - functions which call this symbol
        :param num_args: Number of function arguments
        :returns: Symbol
        """
        ##init BasicBlockSequence
        super(Symbol, self).__init__(config, *args, **kwargs)

        self.name = name
        self.real_name = real_name
        self.bin_name = bin_name
        self.path = path
        self.optimisation = optimisation
        self.compiler = compiler
        self.type = type
        self.linkage = linkage
        self._id = _id
        self.closure = closure
        self.binding = binding
        self.num_args = num_args
        self.arguments = arguments
        self.heap_arguments = heap_arguments
        self.tls_arguments = tls_arguments
        self.local_stack_bytes      = local_stack_bytes
        self.sse                    = sse
        self.tainted_args           = tainted_args
        self.tainted_args_closure   = tainted_args_closure
        self.node_embedding         = node_embedding
        self.icfg_embedding         = icfg_embedding
        self.signature              = signature



    def __getstate__(self):
        utils._desyl_deinit_class_(self)
        return self.__dict__

    def __setstate__(self, state):
        self.__dict__ = state
        utils._desyl_init_class_(self, Config())

    def clone(self):
        #return copy.deepcopy(self)
        return Symbol.from_dict( self.config, self.to_dict(verbose=True) )

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        """
        for key in self.__dict__:
            if self.__dict__[key] != other.__dict__[key]:
                print("KEY {} IS NOT EQUAL".format(key) )
                return False
        return True
        """
        return self.to_json(verbose=True) == other.to_json(verbose=True)

    def __hash__(self):
        return hash(self.__dict__)

    #Return a string that can be used by dress to write this symbol
    #into a stripped binary.
    def get_dress_info(self):
        line = "%s() @ *%s ^%d^\n"%(self.name, self.vaddr, self.size)
        return line


    def analyse(self, binary, r2_pipe_hdlr=None):
        """
            Lift Symbol into VEX and analyse it
            """
        super(Symbol, self).analyse(binary, r2_pipe_hdlr=r2_pipe_hdlr)
        self.num_args = len(self.arguments)

    def sha256(self):
        hash_sha256 = hashlib.sha256()
        hash_sha256.update(self.data)
        return hash_sha256.hexdigest().encode('ascii')


    def _to_vec_tainted_args(self, taint_struct: dict):
        """
            Compute vector representation of tainted args field

                In [18]: s.tainted_args_closure
                Out[18]:
                {'rsi': {'getenv': {'rsi'},
                  'set_program_name': {'rdi', 'rsi'},
                  'strcmp': {'rdi'},
                  'fputs_unlocked': {'r9', 'rcx', 'rdi', 'rdx'},
                  'overflow': {'r9', 'rcx', 'rdx'},
                  'strrchr': {'rdi'}},
                 'rdi': {},
                 'rdx': {'getenv': {'rdx'},
                  'set_program_name': {'rdx'},
                  'setlocale': {'rdx'},
                  'bindtextdomain': {'rdx'},
                  'textdomain': {'rdx'},
                  'atexit': {'rdx'},
                  'strcmp': {'rdx'},
                  'fputs_unlocked': {'rdx'},
                  'overflow': {'rdx'},
                  'usage': {'rdx'}}}
        """
        arg_regs    = [ 'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9' ]
        vec = np.zeros(len(arg_regs)*2, dtype=np.float64)
        for i, arg in enumerate(arg_regs):
            if arg in taint_struct:
                arg_flows           = taint_struct[arg]
                diff_flows_count    = len(arg_flows)
                ##count total flows per func
                total_flows_count   = 0
                for k, v in arg_flows.items():
                    total_flows_count += len(v)

                vec[i*2]        = diff_flows_count
                vec[(i*2)+1]    = total_flows_count

        #TODO: include name information for flows somehow
        return vec
        
    # Punstrip: 2019 USENIX
    """
        def to_vec(self, E):
            
                Convert this symbol to a vector under to configuration of Experiment E
            
            dim = (7,)
            vec = np.zeros(dim, dtype=np.uint64)

            vec_format = [
                "size in bytes (1)",
                "number of callers (1)",
                "number of callees (1)",
                "number of jumps (1)",
                "number of function arguments (1)",
                "number of VEX instruction (1)",
                "number of VEX temporary vars (1)",
                "function arguments as vector (6)"
                "callers as labels (N)",
                "callees as labels (N)",
                "operations as a vector (O)",
                "jumpkinds as a vector (J)",
                "CFG as vec (CFG)",
                "(vex sse) number of bytes used on stack (1)",
                "(vex sse) number of bytes used on heap (1)",
                "(vex sse) number of bytes used for stack arguments (1)",
                #for i in range(1+6):
                # initial is all argumnets tainted, followed by individually
                    #"(vex sse) data-dependency tainted flows to function as a name vector + argumnet position (N*6)",
                    "(vex sse) data-dependency tainted register classes a register_vector (8)",
                    "(vex sse) tainted number of bytes used on stack (1)",
                    "(vex sse) tainted number of bytes used on heap (1)",
                    "(vex sse) tainted number of bytes used as stack arguments (1)",
                    "(vex sse) number of tainted jumps (1) i.e. jumps to code locations that depend on tainted variable",
            ]

            vec[0] = self.size
            vec[1] = len(self.callers)
            vec[2] = len(self.callees)
            vec[3] = len(self.vex['jumpkinds'])
            vec[4] = self.num_args
            vec[5] = self.vex['ninstructions']
            vec[6] = self.vex['ntemp_vars']

            func_args_vec   = E.to_vec('func_arg_vector', self.vex['arguments'])
            operations_vec  = E.to_vec('operations_vector', self.vex['operations'])
            jumpkinds_vec   = E.to_vec('jumpkinds_vector', self.vex['jumpkinds'])
            callees_vec     = E.to_vec('name_vector', self.callees) 

            sse_vec = np.zeros((3, ), dtype=np.uint64)
            sse_vec[0] = len(self.sse['stack_vars'])
            sse_vec[1] = len(self.sse['heap_vars'])
            sse_vec[2] = len(self.sse['stack_args'])
            for i in range(7):
                sse_taint_vec = np.zeros((14,), dtype=np.uint64)
                if i < len(self.sse['taints']):
                    sse_taint_vec[0] = len(self.sse['taints'][i]['t_stack_vars'])
                    sse_taint_vec[1] = len(self.sse['taints'][i]['t_heap_vars'])
                    sse_taint_vec[2] = len(self.sse['taints'][i]['t_stack_args'])
                    sse_taint_vec[3] = len(self.sse['taints'][i]['t_code_locs'])
                    sse_taint_vec[4] = self.sse['taints'][i]['flows']
                    sse_taint_vec[5] = self.sse['taints'][i]['tainted']
                    for j in range(len(self.sse['taints'][i]['register_classes'])):
                        sse_taint_vec[6+j] = self.sse['taints'][i]['register_classes'][j]

                ##add taint vec to main sse vec
                sse_vec = np.hstack([sse_vec, sse_taint_vec])

            return np.hstack( [vec, func_args_vec, operations_vec, jumpkinds_vec, sse_vec ] ).reshape(1, -1)
    """
    
    # Quantitative Features
    """
    self.size                                # Size of the symbol in bytes
    self.vex['ninstructions']                # Number of IR instructions
    

    self.vex['jumpkinds']                    # Sum of one-hot-encoded vectors of branch types
    self.vex['ntemp_vars']                   # Number of temporary variables in the IR
    self.vex['operations']                   # Sum of one-hot-encoded vectors of IR elements

    len(self.callers)                        # Number of callers
    len(self.callees)                        # Number of callees
    len(self.closure)                        # Number of transitively reachable functions

    
    self.icfg_embedding                      # Vector representation of the function CFG
    self.node_embedding                      # Vector representation of the function node in the binary callgraph
    
    len(self.sse['stack_vars'])              # Number of bytes referenced on the stack      
    len(self.sse['heap_vars'])               # Number of bytes referenced on the heap
    len(self.tls)                            # Number of bytes referenced in Thread Local Storage
    self.num_args                            # Number of function arguments    
    len(self.local_stack_bytes)              # Number of bytes used for local variables on the stack

    self.sse['taints']["register_classes"]   # One-hot encoded vector of tainted register types
    len(self.sse['taints']["t_heap_vars"])   # Number of tainted bytes of the heap
    len(self.sse['taints']["t_stack_vars"])  # Number of tainted bytes of the stack
    len(self.sse['taints']["t_stack_args"])  # Number of tainted bytes in arguments to other functions
    len(self.sse['taints']["t_code_locs"])   # Number of conditional jumps that depend on a tainted variable

    
    len(self.tainted_flows)                  # Number of tainted flows to other functions        
    """
    
    # Categorical Features
    """
    self.opcode_hash                        # Common SHA-256 hashes of assembly opcodes
    self.opcode_minhash                     # Common MinHash hashes of assembly opcodes

    self.vex['constants']                   # Common constants referenced
    self.callees                            # Names of dynamically linked callees
    self.closure                            # Known function names reachable from this function

    self.imported_data_refs                 # References to known data objects in dynamically linked libraries
    self.tainted_flows                      # Names of dynamic functions and argument registers tainted
    """

    def to_vec(self, E, nlp, KNOWN_FUNCS, argsD):
        """
            Convert this symbol to a vector under to configuration of Experiment E
        """
        filtered_funcs = set(KNOWN_FUNCS)
        dim = (16,)
        vec = np.zeros(dim, dtype=np.uint64)     # DIM: 16
        
        # Quantitative Features
        vec[0]  =  self.size                               # Size of the symbol in bytes
        vec[1]  = self.vex['ninstructions']                # Number of IR instructions
        vec[2]  = self.vex['ntemp_vars']                   # Number of temporary variables in the IR
        vec[3]  = len(self.callers)                        # Number of callers
        vec[4]  = len(self.callees)                        # Number of callees
        vec[5]  = len(self.closure)                        # Number of transitively reachable functions
        vec[6]  = len(self.sse['stack_vars'])              # Number of bytes referenced on the stack      
        vec[7]  = len(self.sse['heap_vars'])               # Number of bytes referenced on the heap
        vec[8]  = len(self.tls_arguments)                  # Number of bytes referenced in Thread Local Storage
        vec[9]  = self.num_args                            # Number of function arguments    
        vec[10] = self.local_stack_bytes                   # Number of bytes used for local variables on the stack
        vec[11] = len(self.sse['taints']["t_heap_vars"])   # Number of tainted bytes of the heap
        vec[12] = len(self.sse['taints']["t_stack_vars"])  # Number of tainted bytes of the stack
        vec[13] = len(self.sse['taints']["t_stack_args"])  # Number of tainted bytes in arguments to other functions
        vec[14] = len(self.sse['taints']["t_code_locs"])   # Number of conditional jumps that depend on a tainted variable        
        vec[15] = len(self.tainted_flows)                  # Number of tainted flows to other functions


        jumpkinds_vec   = E.to_vec('jumpkinds_vector', self.vex['jumpkinds'])     # Sum of one-hot-encoded vectors of branch types # DIM: J
        operations_vec  = E.to_vec('operations_vector', self.vex['operations'])   # Sum of one-hot-encoded vectors of IR elements  # DIM: O

        icfg_vec    = self.icfg_embedding # Vector representation of the function CFG                           # DIM: 240
        node_vec    = self.node_embedding # Vector representation of the function node in the binary callgraph  # DIM: 136
        
        # Fix broken embeddings
        if icfg_vec is None:
            icfg_vec = np.zeros((240, ), dtype=np.float64)
        if node_vec is None:
            node_vec = np.zeros((136, ), dtype=np.float64)


        tainted_register_types = self.registers_to_vec_classes(set(self.sse['taints']["register_classes"]))  # One-hot encoded vector of tainted register types # DIM: 8
                
        quantD = {"small_vec":vec, "jumpkinds_vec":jumpkinds_vec, "operations_vec":operations_vec, "icfg_vec": icfg_vec, "node_vec":node_vec, "tainted_register_types": tainted_register_types}
        quant_vec = []
        for f in quantD:
            if argsD[f]:
                quant_vec += [ quantD[f] ]
        quant_vec = np.hstack( quant_vec ).reshape(1, -1).astype('float64')
        
        #quant_vec = np.hstack( [vec, jumpkinds_vec, operations_vec, icfg_vec, node_vec,  tainted_register_types] ).reshape(1, -1).astype('float64')        
        
        # Categorical Features

        vec_proj_type       = 'token_vector'
        sparse_vec_type     = 'lil'
        vec_proj            = lambda x: nlp.canonical_set(x)
        
        # Common SHA-256 hashes of assembly opcodes
        common_hashes       = [ self.opcode_hash ] if self.opcode_hash in E.hashes else []
        opcode_hashes_vec   = E.to_sparse_vec('hashes_vector', common_hashes, sparse_vec_type)
        
        # Common MinHash hashes of assembly opcodes
        opcode_minhash =  hashlib.md5(self.opcode_minhash.view(np.uint8)).hexdigest()
        common_min_hashes       = [ opcode_minhash ] if opcode_minhash in E.minhashes else []
        opcode_minhashes_vec   = E.to_sparse_vec('minhashes_vector', common_min_hashes, sparse_vec_type)
        
        # Common constants referenced
        id_consts   = list(filter(lambda x: x in E.constants, self.vex['constants']))
        consts_vec  = E.to_sparse_vec('constants_vector', id_consts, sparse_vec_type)     
        
        # Names of dynamically linked callees
        mod_callees = list(filter(lambda x: x in filtered_funcs, self.callees))
        callees_vec = reduce(lambda x,y: x + y, map(lambda x, f=vec_proj, t=sparse_vec_type: E.to_sparse_vec(vec_proj_type, f(x), t), mod_callees), E.to_sparse_vec(vec_proj_type, [], sparse_vec_type))

        # Names of dynamically linked callers
        mod_callers = list(filter(lambda x: x in filtered_funcs, self.callers))
        callers_vec = reduce(lambda x,y: x + y, map(lambda x, f=vec_proj, t=sparse_vec_type: E.to_sparse_vec(vec_proj_type, f(x), t), mod_callers), E.to_sparse_vec(vec_proj_type, [], sparse_vec_type))
        
        # Known function names reachable from this function
        mod_closure = list(filter(lambda x: x in filtered_funcs, self.closure)) 
        closure_vec = reduce(lambda x,y: x + y, map(lambda x, f=vec_proj, t=sparse_vec_type: E.to_sparse_vec(vec_proj_type, f(x), t), mod_closure), E.to_sparse_vec(vec_proj_type, [], sparse_vec_type))
        
        # References to known data objects in dynamically linked libraries
        imported_data_refs   = list(filter(lambda x: x in E.imported_data_refs, self.imported_data_refs))
        data_refs_vector = E.to_sparse_vec('imported_data_refs_vector', imported_data_refs, sparse_vec_type)

        # Names of dynamic functions and argument registers tainted
        a = archinfo.ArchAMD64()
        regs = []
        for vex_offset in a.argument_registers:
            reg = a.translate_register_name(vex_offset)
            regs.append(reg)            
        regs.append('rax')
        regs = list(regs)
        regs.sort()            
        tflows_vec = np.zeros(len(regs), dtype=np.uint64) 
        for tfunc, tregs in self.tainted_flows:
            for reg in tregs:
                if reg in regs:
                    i = regs.index(reg)
                    tflows_vec[i] += 1

        """need to filter on known functions
        below cheats, uses name of other functions
        t_flow_vec = E.to_vec('name_vector', [])"""
        t_flow_vec = E.to_sparse_vec(vec_proj_type, [], sparse_vec_type) 
        for flow in self.tainted_flows:
            func, args = flow
            if func not in filtered_funcs:
                continue
            try:
                #t_vec = E.to_vec('name_vector', [func])
                t_vec = E.to_sparse_vec(vec_proj_type, vec_proj(func), sparse_vec_type)
                t_flow_vec += (len(args) * t_vec)
                #print("Added dynamic func call {} to vector".format(func))
            except:
                #print("[-!] Failed to add {} to dyn func call".format(func))
                pass
         
        categD = {"opcode_hashes_vec":opcode_hashes_vec, "opcode_minhashes_vec":opcode_minhashes_vec, "consts_vec":consts_vec, "callees_vec": callees_vec, "callers_vec": callers_vec, "closure_vec":closure_vec, "data_refs_vec": data_refs_vector, "tflows_vec":tflows_vec}
        catag_vec = []
        for f in categD:
            if argsD[f]:
                catag_vec += [ categD[f] ]
        
        catag_vec   = sp.sparse.hstack( catag_vec )
        #catag_vec   = sp.sparse.hstack( [opcode_hashes_vec, opcode_minhashes_vec, consts_vec, callees_vec, closure_vec, data_refs_vector, tflows_vec] )
        
        # Forcing values in catagorical vector to be 0 or 1
        above_one = catag_vec > 1.0
        # convert to csr to enable int indexing
        catag_vec = catag_vec.tocsr()
        for i, j in zip(*above_one.nonzero()):
            catag_vec[i, j] = 1.0
        # sore as coo, efficient storagen, no indexing
        catag_vec = catag_vec.tocoo()

        return quant_vec, catag_vec
        
    @staticmethod
    def registers_to_vec_classes(regs):
        """
            Convert a list of registers (possible tainted) to 
            a vector of 

            Classes = [
                return 
                general purpose registers
                stack pointer
                instruction pointer
                base pointer
                floating point register
                f segment
                g segment
            ]
        """
        assert(isinstance(regs, set))
        #vec = np.zeros((1, 8), dtype=np.uint64)
        vec = [0] * 8

        ret_regs = set(['rax', 'xmm0'])
        general_purpose = set([ 'rbx', 'rcx', 'rdx' ] + list(map(lambda x: 'r' + str(x), range(16))))
        floating_point = set(map(lambda x: 'zmm' + str(x), range(32)))
        fs = set([ 'fs' ])
        gs = set([ 'gs' ])
        stack_pointer = set(['rsp'])
        base_pointer = set(['rbp'])
        inst_pointer = set(['rip'])

        for i, reg_class in enumerate([ret_regs, general_purpose, stack_pointer, inst_pointer, base_pointer, floating_point, fs, gs]):
            if len(regs.intersection(reg_class)) > 0:
                vec[i] = 1
        return vec


