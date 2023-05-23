#!/usr/bin/pyhton3
import sys

import socket, pickle
import copy
import json
import bson
import os
import hashlib
import re
import binascii
import subprocess
import pymongo
import pprint
import math
import networkx as nx
from networkx.drawing import nx_agraph
#from asciinet import graph_to_ascii
import pygraphviz
import r2pipe
import tqdm
import logging
import numpy as np
import scipy as sp
import archinfo
from functools import reduce
import IPython

#from classes.config import Config
import context
from classes.config import Config
from classes.basicblocksequence import BasicBlockSequence
from classes.basicblock import BasicBlock
import classes.utils
from scripts.gk_weisfeiler_lehman import GK_WL

class Symbol(BasicBlockSequence):
    """
    def __init__(self, config, name="", bin_name="", size=-1, vaddr=-1,
            hash=b'', opcode_hash=b'', data=b'', path="", optimisation=-1, 
            compiler="", type="", linkage="", _id=-1, vex={}, bbs=[], nargs=-1,
            arch="x86_64", cfg=None, callers=[], callees=[], asm=[], opcodes=[],
            binding="unknown", num_args=-1, *args, **kwargs):
    """

    def __init__(self, config, name="", real_name="", bin_name="", path="", optimisation=-1, 
            compiler="", type="", linkage="", _id=-1, sse={}, closure=[],
            arguments=[], heap_arguments=[], local_stack_bytes=0, tls_arguments=[],
            binding="unknown", num_args=-1, *args, **kwargs):
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
        self.local_stack_bytes = local_stack_bytes
        self.sse = sse

        ##Convert MongoDB _ID instances
        if isinstance(_id, str):
            if _id != "-1":
                self._id = bson.ObjectId(_id)

    def __getstate__(self):
        classes.utils._desyl_deinit_class_(self)
        return self.__dict__

    def __setstate__(self, state):
        self.__dict__ = state
        classes.utils._desyl_init_class_(self, Config())

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

    #Binary data is printing as hex string! Nothing prepends string e.g. "0x"
    def __str__(self):
        return self.to_str_short()

    def to_str_custom(self, proj):
        dict_obj = self.to_dict(verbose=True)
        new_dict = {}
        for key in proj:
            new_dict[key] = dict_obj[key]

        return json.dumps( new_dict )

    def to_str_short(self):
        proj = [ 'name', 'optimisation', 'bin_name', 'compiler', 'vaddr', 'path' ]
        return self.to_str_custom(proj)

    def to_str_full(self):
        return self.to_json(verbose=True, include_id=True)

    #create new symbols from database
    @staticmethod
    def fromDatabase(db, _id):
        collection_name = db.collection_name + db.config.database.symbol_collection_suffix
        #print("Trying to find symbol with id: {} from collection {}".format(_id, coll_name))
        db.logger.debug("Trying to find symbol with id: {} from collection {}".format(_id, collection_name))
        #assert(False and "Error need to change _id and coll_name around")

        if isinstance(_id, str):
            _id = bson.ObjectId(_id)

        j = db.client[collection_name].find_one({'_id': _id})

        assert(j)
        assert(isinstance(j['cfg'], str))
        assert(isinstance(j['hash'], str))
        assert(isinstance(j['opcode_hash'], str))
        assert(isinstance(j['vaddr'], int))
        assert(isinstance(j['size'], int))
        assert(isinstance(j['binding'], str))
        assert(isinstance(j['_id'], bson.ObjectId))
        assert(str(j['_id']) != "-1")

        return Symbol.from_dict(db.config, j)

    #find the current symbol in the database
    def find_symbol(self, db, collection_name=''):
        if len(collection_name) == 0:
            collection_name = self.config.database.collection_name
        symb = self.to_dict()
        if isinstance(symb['_id'], str):
            symb['_id'] = bson.ObjectId(symb['_id'])
        return db[collection_name].find(symb)

    #save symbol to mongo db
    def save_to_db(self, db):
        collection_name = db.collection_name + self.config.database.symbol_collection_suffix
        #convert string to objectid
        if (isinstance(self._id, str) and self._id != "-1") or isinstance(self._id, bson.ObjectId):
            t = self.to_dict(include_id=True)
            t['_id'] = bson.ObjectId(t['_id'])
            db.client[collection_name].update({ '_id': t['_id']}, t, upsert=True)
            return t['_id']
        else:
            t = self.to_dict(include_id=False)
            res = db.client[collection_name].insert_one( t )
            self._id = res.inserted_id
            return self._id

    #### Warning, id is not taken into account!
    @staticmethod
    def save_to_db_many(symbols, db):
        collection_name = db.collection_name + db.config.database.symbol_collection_suffix
        inserted = []
        N = 64
        ##stop writing 50,000 symbols to database at the same time
        for _symbs in tqdm.tqdm(classes.utils.chunks_of_size(symbols, N), desc='Saving symbols to DB', unit_scale=N):
            try:
                symbol_dicts = list(map( lambda x: x.to_dict(include_id=False), _symbs))
                #res = db[collection_name].insert_many( symbol_dicts, write_concern = pymongo.WriteConcern(j=False,w=0), ordered=False )
                #res = db[collection_name].insert_many( symbol_dicts, write_concern = pymongo.WriteConcern(w=0), ordered=False )
                #res = db[collection_name].insert_many( symbol_dicts, bypass_document_validation=False, ordered=False )
                res = db.client[collection_name].insert_many( symbol_dicts )
                inserted += res.inserted_ids
            except Exception as e:
                print("Error occured during db insertion")
                print(e)
                IPython.embed()
                raise e
        return inserted

    def to_json(self, verbose=False, include_id=False):
        return json.dumps( self.to_dict(verbose=verbose, include_id=include_id), sort_keys=True, indent=4)

    def to_dict(self, verbose=False, include_id=False):
        dict_obj = { 
            "name"          : self.name,
            "real_name"     : self.real_name,
            "linkage"       : self.linkage,
            "bin_name"      : self.bin_name,
            "path"          : self.path,
            "optimisation"  : self.optimisation,
            "type"          : self.type,
            "compiler"      : self.compiler,
            "binding"       : self.binding,
            "num_args"      : self.num_args,
            "closure"       : list(self.closure),
            "local_stack_bytes"        : self.local_stack_bytes,
            "arguments"     : list(self.arguments),
            "heap_arguments": list(self.heap_arguments),
            "_id"           : self._id
        }

        parent_dict = super(Symbol, self).to_dict(verbose=verbose)
        dict_obj.update( parent_dict )

        ##include MongoDB ID
        if include_id:
            if isinstance(dict_obj['_id'], bson.ObjectId):
                dict_obj['_id'] = str( dict_obj['_id'] )
        else:
            del dict_obj['_id']

        return dict_obj

    @staticmethod
    def from_dict(config, dict_obj):
        assert(isinstance(dict_obj, dict))

        #s = Symbol(config) 
        #This is incredibly slow, have default dict object instead

        default_dict = {
                "name" : "", 
                "real_name" : "", 
                "bin_name":"",
                "path":"", "optimisation":-1, 
                "compiler":"", "type":"", "linkage":"", "_id":-1,
                "binding":"unknown", "num_args":-1,
                "size"          : -1, 
                "vaddr"         : -1, 
                "data"          : b'', 
                "vex"           : {}, 
                "cfg"           : None,
                "asm"           : [], 
                "opcodes"       : [], 
                "arch"          : "", 
                "bbs"           : [], 
                "hash"          : b'',
                "opcode_hash"   : b'',
                "callees"       : [], 
                "callers"       : [],
                'arguments'     : [],
                "heap_arguments": [],
                "local_stack_bytes"        : -1,
                "closure"       : []
        }

        default_dict.update(dict_obj)
        n = default_dict

        return Symbol(config, bbs=n['bbs'], size=n['size'], vaddr=n['vaddr'], 
            data=n['data'], vex=n['vex'], cfg=n['cfg'], asm=n['asm'], 
            opcodes=n['opcodes'],  callees=n['callees'], callers=n['callers'], 
            name=n['name'], 
            real_name=n['real_name'], 
            linkage=n['linkage'], bin_name=n['bin_name'], path=n['path'], 
            optimisation=n['optimisation'], arch=n['arch'], type=n['type'], 
            compiler=n['compiler'], _id=n['_id'],  
            num_args=n['num_args'], hash=n['hash'], 
            arguments=n['arguments'], local_stack_bytes=n['local_stack_bytes'],
            heap_arguments=n['heap_arguments'], closure=n['closure'],
            opcode_hash=n['opcode_hash'], binding=n['binding'])

    @staticmethod
    def from_json(config, json_str):
        dict_obj = json.loads( json_str )
        return Symbol.from_dict(config, dict_obj)

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

    def to_vec(self, E, KNOWN_FUNCS=[], name_info=True):
        """
            Convert this symbol to a vector under to configuration of Experiment E
        """
        filtered_funcs = set(KNOWN_FUNCS)
        dim = (14,)
        vec = np.zeros(dim, dtype=np.uint64)
        nlp = classes.NLP.NLP(self.config)

        vec[0] = self.size
        vec[1] = len(self.callers)
        vec[2] = len(self.callees)
        vec[3] = len(self.vex['jumpkinds'])
        vec[4] = self.num_args
        vec[5] = self.vex['ninstructions']
        vec[6] = self.vex['ntemp_vars']
        vec[7] = len(self.closure)
        vec[8] = len(self.tainted_flows)
        vec[9] = self.local_stack_bytes
        vec[10] = len(self.heap_arguments)
        vec[11] = len(self.tls_arguments)
        ##internal vex callees
        vec[12] = len(self.vex['callees'])
        vec[13] = len(self.closure)

        func_args_vec   = E.to_vec('func_arg_vector', self.arguments)
        operations_vec  = E.to_vec('operations_vector', self.vex['operations'])
        jumpkinds_vec   = E.to_vec('jumpkinds_vector', self.vex['jumpkinds'])

        mod_callees = list(filter(lambda x: x in filtered_funcs, self.callees))
        mod_callers = list(filter(lambda x: x in filtered_funcs, self.callers))
        mod_closure = list(filter(lambda x: x in filtered_funcs, self.closure))
        #closure_vec     = E.to_vec('ml_name_vector', mod_closure) 

        vec_proj_type       = 'name_vector'
        sparse_vec_type     = 'lil'
        vec_proj            = lambda x: [x]

        callees_vec     = reduce(lambda x,y: x + y, map(lambda x, f=vec_proj, t=sparse_vec_type: E.to_sparse_vec(vec_proj_type, f(x), t), mod_callees),
            E.to_sparse_vec(vec_proj_type, [], sparse_vec_type))
        callers_vec     = reduce(lambda x,y: x + y, map(lambda x, f=vec_proj, t=sparse_vec_type: E.to_sparse_vec(vec_proj_type, f(x), t), mod_callers),
            E.to_sparse_vec(vec_proj_type, [], sparse_vec_type))
        closure_vec     = reduce(lambda x,y: x + y, map(lambda x, f=vec_proj, t=sparse_vec_type: E.to_sparse_vec(vec_proj_type, f(x), t), mod_closure),
            E.to_sparse_vec(vec_proj_type, [], sparse_vec_type))

        name_vec        = E.to_sparse_vec(vec_proj_type, [], sparse_vec_type)
        if self.name in KNOWN_FUNCS:
            name_vec    = E.to_sparse_vec(vec_proj_type, vec_proj(self.name), sparse_vec_type)

        if isinstance(self.cfg, str): 
            self.cfg = classes.utils.str_to_nx(self.cfg)

        cfg_vec = E.to_vec('cfg_vector', self.cfg)

        #tainted flows vector
        a = archinfo.ArchAMD64()
        regs = set(["rax"])
        for vex_offset in a.argument_registers:
            reg = a.vex_reg_offset_to_name[ vex_offset ]
            name, offset = reg
            regs.add( name )

        regs = list(regs)
        regs.sort()
        
        tflows_vec = np.zeros(len(regs), dtype=np.uint64)
        for tfunc, tregs in self.tainted_flows:
            for reg in tregs:
                if reg in regs:
                    i = regs.index(reg)
                    tflows_vec[i] += 1

        num_flow_vec = np.array(len(self.tainted_flows))
        ##need to filter on known functions
        ##below cheats, uses name of other functions
        #t_flow_vec = E.to_vec('name_vector', [])
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
                print("[-!] Failed to add {} to dyn func call".format(func))
                pass

        id_consts   = list(filter(lambda x: x in E.constants, self.vex['constants']))
        consts_vec  = E.to_sparse_vec('constants_vector', id_consts, sparse_vec_type)

        common_hashes       = [ self.opcode_hash ] if self.opcode_hash in E.hashes else []
        opcode_hashes_vec   = E.to_sparse_vec('hashes_vector', common_hashes, sparse_vec_type)

        #registers_to_vec_classes()

        ##splitting of categorical from quatitative vectors
        quant_vec   = np.hstack( [vec, func_args_vec, operations_vec, jumpkinds_vec, num_flow_vec, cfg_vec] ).reshape(1, -1).astype('float64')
        catag_vec   = sp.sparse.hstack( [callees_vec, callers_vec, closure_vec, opcode_hashes_vec, consts_vec, tflows_vec] )
        #return np.hstack( [vec, func_args_vec, operations_vec, jumpkinds_vec, tflows_vec, opcode_hashes_vec, cfg_vec, consts_vec] ).reshape(1, -1)
        return quant_vec, catag_vec


    def to_context_vec(self, E, binary, KNOWN_FUNCS=[]):
        """
            Convert this symbol to a vector under to configuration of Experiment E and a binary 
            Include information from d callers and callee away from this vector in this vector representation
        """
        quant_vec, catag_vec        = self.to_vec(E, KNOWN_FUNCS=KNOWN_FUNCS)
        callee_q_vec, callee_c_vec  = 0*copy.deepcopy(quant_vec), 0*copy.deepcopy(catag_vec)
        caller_q_vec, caller_c_vec  = 0*copy.deepcopy(quant_vec), 0*copy.deepcopy(catag_vec)

        for s in self.callees:
            c = binary.get_symbol_desc({ 'real_name' : s.real_name,  'vaddr': s.vaddr })
            c_q_v, c_c_v = c.to_vec(E, KNOWN_FUNCS=KNOWN_FUNCS)
            callee_q_vec += c_q_v
            callee_c_vec += c_c_v

        for s in self.callers:
            c = binary.get_symbol_desc({ 'real_name' : s.real_name,  'vaddr': s.vaddr })
            c_q_v, c_c_v = c.to_vec(E, KNOWN_FUNCS=KNOWN_FUNCS)
            caller_q_vec += c_q_v
            caller_c_vec += c_c_v

        return (quant_vec, catag_vec), (callee_q_vec, callee_c_vec), (caller_q_vec, caller_c_vec)

    @staticmethod
    def registers_to_vec_classes(regs):
        """
            Convert a list of registers (possible tainted) to 
            a vector of classes.

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


