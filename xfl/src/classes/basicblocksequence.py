#!/usr/bin/pyhton3
#allow analysing from raw data without r2 and binary
import os, sys, copy
import json, math, re
import binascii
import collections
import pprint
import logging
import time
import numpy as np
from functools import reduce
import networkx as nx
from networkx.drawing import nx_agraph
import timeout_decorator
import pygraphviz
import IPython
import hashlib
#from numba import jit
import collections
import claripy

#from classes.config import Config
import context
import classes.utils
from classes.config import Config
from classes.basicblock import BasicBlock, VEXLiftingError, NoNativeInstructionsError, LiveVariables, TaintTracking
from classes.symbolic_execution_engine import SymbolicExecutionEngine
import scripts.vex_classification as vexc
#from scripts.gk_weisfeiler_lehman import GK_WL
import classes.database
import classes.pmfs


"""
    BasicBlockSequence contains the properties of a basicblock (hash, data, ...) over the entire sequence of basicblocks as well as a list of basicblocks
"""
class BasicBlockSequence():
    STRICT_MODE = True
    PARSE_CFG   = False

    def __init__(self, config, bbs=copy.deepcopy([]), size=-1, vaddr=-1,data=b'', vex=copy.deepcopy({}), arch="",
            asm=copy.deepcopy([]), opcodes=copy.deepcopy([]), hash=b'', opcode_hash=b'', cfg=nx.DiGraph(),
            callers=copy.deepcopy(set([])), callees=copy.deepcopy(set([])), tainted_flows=[], arguments=[]):
        """
            Data passed in may be null, may need to wait for r2pipe to get data from fill_bytes()

            :param config: DESYL Config
            :param bbs: List of BasicBlocks
            :param size: Size in bytes of this BasicBlockSequence
            :param vaddr: Virtual Address at the start of the BBS
            :param data: Binary data of BBS
            :param vex: VEX info about BBS
            :param cfg: CFG of BBS
            :param asm: List of ASM that make up the BBS
            :param opcodes: List of ASM opcodes
        """
        classes.utils._desyl_init_class_(self, config)

        if BasicBlockSequence.STRICT_MODE:
            assert(isinstance(bbs, list))
            for bb in bbs:
                assert(isinstance(bb, BasicBlock))

            # BB constructor checks
            assert(isinstance(size, int))
            #assert(isinstance(vaddr, int))
            if not isinstance(vaddr, int):
                vaddr = -1
            assert(isinstance(opcodes, list))
            assert(isinstance(asm, list))
            assert(not vex or isinstance(vex, dict))
            assert(isinstance(data, bytes) or isinstance(data, str))
            assert(isinstance(hash, bytes) or isinstance(hash, str))
            assert(isinstance(opcode_hash, bytes) or isinstance(opcode_hash, str))

        self.vaddr = vaddr
        self.size = size
        self.data = data
        self.arch = arch
        self.vex = vex
        self.asm = list(asm)
        self.opcodes = list(opcodes)
        self.hash = hash
        self.opcode_hash = opcode_hash
        self.callers = set(callers)
        self.callees = set(callees)
        self.cfg = cfg
        self.arguments = set(arguments)
        self.tainted_flows = list(tainted_flows)

        ##Parsing 1000's BBS CFGs take a very long time
        if BasicBlockSequence.PARSE_CFG:
            if isinstance(cfg, str):
                #self.cfg = nx_agraph.from_agraph( pygraphviz.AGraph(cfg) )
                self.cfg = classes.utils.str_to_nx( cfg )
            elif isinstance(cfg, nx.DiGraph):
                self.cfg = cfg
            else:
                self.logger.debug("Initailising blank CFG")
                self.cfg = nx.DiGraph()

        ##convert from string to binary
        for attr in [ "data", "hash", "opcode_hash" ]:
            if isinstance(self.__getattribute__(attr), str):
                self.__setattr__(attr, binascii.unhexlify( self.__getattribute__(attr) ) )

        if BasicBlockSequence.STRICT_MODE:
            for attr in [ "data", "hash", "opcode_hash" ]:
                if not isinstance( self.__getattribute__(attr), bytes):
                    print("Incorrect data type for BasicBlockSequence.data - {}".format(type(self.data)))
                    IPython.embed()
                    raise RuntimeError("Incorrect data type for BasicBlockSequence.data - {}".format(type(self.data)))

        #create fresh copy from old bbs
        self.bbs = copy.deepcopy( bbs )



    def __getstate__(self):
        classes.utils._desyl_deinit_class_(self)
        return self.__dict__

    def __setstate__(self, state):
        self.__dict__ = state
        classes.utils._desyl_init_class_(self, Config())



    def bbs_from_data(self):
        """
        Algorithm GetBasicBlocks:
            a) The first statement is the program is a leader
            b) A statement that is the target of an unconditional or conditional goto is a leader
            c) Any statement following a unconditional or conditional goto is a leader


            NB: Forces correct decode of instructions to stop short
            alignments/offsets decoding to different instrs
        """
        assert(self.size == len(self.data))
        if self.size == 0:
            return

        #ordered list of vaddrs
        leaders = [self.vaddr] + list(set( BasicBlock.gen_leaders(self.data, self.vaddr, self.arch) ))
        ordered_leaders = sorted(leaders)

        end_vaddr = self.vaddr + self.size
        assert(end_vaddr in ordered_leaders)

        for i, leader in enumerate(ordered_leaders):
            ##if last element
            if leader == end_vaddr:
                continue

            start_offset    = leader - self.vaddr
            end_offset      = ordered_leaders[i+1] - self.vaddr

            #don't insert empty bbs
            if end_offset <= start_offset:
                continue

            try: 
                bb = BasicBlock.from_data( self.data[start_offset:end_offset], 
                                self.vaddr + start_offset, self.arch)

            except NoNativeInstructionsError as e:
                self.logger.warning("Assuming an overlapping basicblock. Trying\
                        to decompile again..")

                #print("Trying again")
                #end_offset  = ordered_leaders[i+1+1] - self.vaddr
                end_offset  = ordered_leaders[i+1] - self.vaddr

                ##add overlapping basicblock
                bb = BasicBlock.from_data( self.data[start_offset:end_offset], 
                                self.vaddr + start_offset, self.arch)

            self.bbs.append(bb)

        self.logger.debug("FUNCTION HAS {} BASIC BLOCKS!".format( len(self.bbs) ))

        for bb in self.bbs:
            if len(bb.data) == 0:
                print("bbs_from_data messed up, could not parse any x86 instrs\
                        (this may be correct)")
                IPython.embed()
                sys.exit()

    #TODO: LAST OPCODE is same as VEX JUMPKIND
    #create BasicBlockSequence from JSON
    @staticmethod
    def fromJSON(j):
        return BasicBlockSequence.from_dict(j)

    def clone(self):
        return copy.deepcopy(self)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __hash__(self):
        return hash(self.__dict__)

    def to_json(self, verbose=False):
        return json.dumps( self.to_dict(verbose=verbose), sort_keys=True, indent=4)

    def to_dict(self, verbose=False):
        dict_obj = { 
            "size"          : copy.deepcopy(self.size), 
            "vaddr"         : copy.deepcopy(self.vaddr), 
            "data"          : binascii.hexlify(self.data).decode('ascii'), 
            "vex"           : copy.deepcopy(self.vex), 
            "cfg"           : classes.utils.nx_to_str(self.cfg) if isinstance(self.cfg, nx.DiGraph) else self.cfg,
            "asm"           : copy.deepcopy(self.asm), 
            "opcodes"       : copy.deepcopy(self.opcodes), 
            "arch"          : copy.deepcopy(self.arch), 
            "hash"          : binascii.hexlify(self.hash).decode('ascii'),
            "opcode_hash"   : binascii.hexlify(self.opcode_hash).decode('ascii'),
            "callees"       : list(copy.deepcopy(self.callees)), 
            "callers"       : list(copy.deepcopy(self.callers)),
            "arguments"     : list(self.arguments),
            "tainted_flows" : list(self.tainted_flows)
        }
        #convert sets to lists for printing to json
        for k in ['constants']:
            if k in dict_obj['vex']:
                dict_obj['vex'][k] = list(dict_obj['vex'][k]) 

        if verbose:
            dict_obj['bbs'] = []
            for i in range(len(self.bbs)):
                dict_obj['bbs'].append(copy.deepcopy(self.bbs[i]).to_dict())

        return dict_obj

    @staticmethod
    def from_dict(dict_obj):
        default_bbs = { 
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
            "arguments"     : [],
            "tainted_flows" : []
        }

        default_bbs.update(dict_obj)
        n = default_bbs
        return BasicBlockSequence(bbs=n['bbs'], size=n['size'], vaddr=n['vaddr'], 
                data=n['data'], vex=n['vex'], cfg=n['cfg'], asm=n['asm'], 
                opcodes=n['opcodes'], callees=n['callees'], 
                callers=n['callers'], hash=n['hash'], 
                opcode_hash=n['opcode_hash'], arguments=n['arguments'],
                tainted_flows=n['tainted_flows']
        )

    @staticmethod
    def from_json(json_str):
        dict_obj = json.loads( json_str )
        return BasicBlockSequence.from_dict( dict_obj )

    def __str__(self):
        return self.to_json()

    #Get a measure of similarity between this BasicBlockSequence and another
    #@jit
    def similarity(self, other, kern_iterations=10):
        sim = []
        #### Symbol size
        size_sim = BasicBlockSequence._num_diff(self.size, other.size)
        #print("size_sim: {}, self.size: {}, other.size: {}".format(size_sim, self.size, other.size))
        sim.append(size_sim)

        #### Symbol hash
        if self.hash != b'' and other.hash != b'':
            hash_sim = 1.0 if self.hash == other.hash else 0.0
            sim.append(hash_sim)
        else:
            sim.append(0.0)

        #### Symbol opcode hash
        if self.opcode_hash != b'' and other.opcode_hash != b'':
            opcode_hash_sim = 1.0 if self.opcode_hash == other.opcode_hash else 0.0
            sim.append(opcode_hash_sim)
        else:
            sim.append(0.0)

        if self.vex and other.vex:
            #### VEX Size       # sim[0]
            vex_ninstr_sim = BasicBlockSequence._num_diff(self.vex['ninstructions'], other.vex['ninstructions'])
            sim.append(vex_ninstr_sim)

            #### VEX number temporary variables
            #vex_nvars_sim = self._num_diff(self.vex['ntemp_vars'], other.vex['ntemp_vars'])
            #sim.append(vex_nvars_sim)

            #### Vex dictionay summary comparision kind
            ## sim[1:5]
            for kind in ["sum_jumpkinds", "temp_vars" ]:
                kind_a = set( self.vex[kind].keys() )
                kind_b = set( other.vex[kind].keys() )

                similar = len( kind_a.intersection(kind_b) )
                max_sim = max( len(kind_a), len(kind_b) )
                if max_sim == 0:
                    sim.append(1.0)
                else:
                    vex_sum_sim = float(similar) / max_sim
                    sim.append(vex_sum_sim)

                #build vector dot product between kinds and numbers
                kind_all = list(kind_a.union(kind_b))
                N = len(kind_all)
                a_kind_vec, b_kind_vec = np.zeros((N,), dtype=np.int), np.zeros((N,), dtype=np.int)
                for i in range(len(kind_all)):
                    if kind_all[i] in kind_a:
                        a_kind_vec[i] += self.vex[kind][kind_all[i]]
                    if kind_all[i] in kind_b:
                        b_kind_vec[i] += float( other.vex[kind][kind_all[i]] )

                dot = float( np.dot(a_kind_vec, b_kind_vec) )
                #magnitude = float( np.linalg.norm(a_kind_vec, ord=2) * np.linalg.norm(b_kind_vec, ord=2) )
                #10x quicker than np.linalg.norm
                magnitude = np.sqrt(a_kind_vec.dot(a_kind_vec)) * np.sqrt(b_kind_vec.dot(b_kind_vec))

                if magnitude == 0.0:
                    sim.append(1.0)
                else:
                    #### Floating point rounding errors!!!
                    #if abs(dot - magnitude) <= 0.000001:
                    #    dot = magnitude

                    if magnitude > 0.0:
                        #float point errors, dot can be bigger
                        magnitude = magnitude if magnitude >= dot else dot
                        vex_kind_sim = 1 - ( math.acos( dot / magnitude ) / (math.pi / 2) )
                    else:
                        vex_kind_sim = 0.0

                    sim.append( round(vex_kind_sim, 5) )

            #### VEX Order of jumpkinds
            ### sim[6]
            for i in range( min(len(self.vex['jumpkinds']), len(other.vex['jumpkinds']) ) ):
                if self.vex['jumpkinds'][i] != other.vex['jumpkinds'][i]:
                    break
            max_vex_order = max( len(self.vex['jumpkinds']), len(other.vex['jumpkinds']) )
            if max_vex_order > 1:
                vex_ordered_jks_sim = float(i + 1) / max_vex_order 
            else:
                vex_ordered_jks_sim = 0

            sim.append(vex_ordered_jks_sim)

            #### Vex constant matching
            #### sim[7]
            self_consts = set( list( map( lambda x: str(x[0]) + "_" + str(x[1]), self.vex['constants'] ) ) )
            other_consts = set( list( map( lambda x: str(x[0]) + "_" + str(x[1]), other.vex['constants'] ) ) )

            similar = len( self_consts.intersection(other_consts) )
            max_sim = max( len(self_consts), len(other_consts) )
            if max_sim == 0:
                sim.append(1.0)
            else:
                vex_consts_sim = float(similar) / max_sim
                sim.append(vex_consts_sim)

            
            #### sim[8:11]
            for ir_type in [ "statements", "operations", "expressions" ]:
                dot_prod = np.dot( self.vex[ir_type], other.vex[ir_type] )
                mag = np.sqrt(self.vex[ir_type].dot(self.vex[ir_type])) * np.sqrt(other.vex[ir_type].dot(other.vex[ir_type]))
                #domain of acos in 1 - -1, 0 is similar, 1 and -1 is not
                #no negative entries so domain should be between 0 - 1 
                #range is between -pi/2 +pi/2
                if mag > 0.0:
                    mag = mag if mag >= dot_prod else dot_prod
                    ir_type_sim = 1 - ( math.acos( dot_prod / mag ) / ( math.pi / 2 ) )
                else:
                    ir_type_sim = 0.0
                #round to 5 decimal places
                sim.append( round(ir_type_sim, 5) )

        #vex not implemented
        elif not self.vex and not other.vex:
            sim += [1.0] * 10
        else:
            sim += [0.0] * 10

        #### CFG BBS number of callees
        callees_size_sim = BasicBlockSequence._num_diff( len(self.callees), len(other.callees) )
        sim.append(callees_size_sim)

        #### CFG BBS number of callers
        callers_size_sim = BasicBlockSequence._num_diff( len(self.callers), len(other.callers) )
        sim.append(callers_size_sim)

        #### Number of basic blocks
        #Should be covered by VEX IR instructions, not helpful here

        #if both symbol shave more than 1 basic block i.e. > 1 edge on a cfg
        #if len(self.bbs) > 1 and len(other.bbs) > 1:
        if self.cfg and other.cfg:
            aNumNodes = len(self.cfg.nodes)
            bNumNodes = len(other.cfg.nodes)


            #if both graphs have nodes and the biggest is less than 3 or they contain 75% of the number of nodes 
            if aNumNodes > 0 and bNumNodes > 0:
                big = max(aNumNodes, bNumNodes)
                small = min(aNumNodes, bNumNodes)
                rel_sim = float(small) / float(big)

                ##2 nodes connected
                if aNumNodes == 2 and bNumNodes == 2:
                    cfg_sim = 1.0

                elif rel_sim > 0.6:
                    #inter bbs cfg comparision using graph kernel
                    #try:
                    kern = GK_WL() 
                    cfg_sim = kern.compare( self.cfg, other.cfg, h=kern_iterations, node_label=False )
                    #except Exception as e:
                    #    self.logger.critical("Error! Exception raised in Graph kernel comparison!")
                    #    self.logger.critical(e)
                    #cfg_sim = 0.0 
                else:
                    cfg_sim = 0.0
            elif aNumNodes == 0 and bNumNodes == 0:
                cfg_sim = 1.0
            else:
                cfg_sim = 0.0

            sim.append(cfg_sim)

        elif self.cfg or other.cfg:
            sim.append(0.0)
        else:
            sim.append(1.0)

        self.logger.debug( json.dumps( list( zip( sim, [
            "size in bytes", 
            "hash",
            "opcode hash",
            "number of VEX IR instructions",
            "sum_jumpkinds :: types", 
            "sum_jumpkinds :: number and type", 
            "temp_vars :: types", 
            "temp_vars :: number and type", 
            "jumpkinds :: order",
            "constants matching :: type and value",
            "statements :: catagorised",
            "operations :: catagorised",
            "expressions :: catagorised",
            "CFG number of callees",
            "CFG number of callers", 
            "gk_weisfeiler_lehman graph kernel" 
        ] ) ) ) )


        #### weightings from old JS implementation
        #[ 0.2, 1.0, 1.0, 0.5, 0.7, 0.3, 1, 1, 1, 1, 1, 0.8, 0.9, 0.9, 0.7, 0.3 ];
        
        #TODO: multiple vector by weightings
        #TODO: Automatically find the best weightings 
        #weightings = [ 0.7, 2.0, 1.5, 0.8, 0.5, 0.85, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.3, 0.85, 1.75 ]
        if len(sim) == 15:
            print(sim)
        w_sim = np.array( BasicBlockSequence.similarity_weightings ) * np.array( sim )

        return w_sim

    def analyse(self, binary, r2_pipe_hdlr=None):
        """
            Analyse BBS: 
                - Lift to VEX
                - Generate Hashes
        """
        ##Still need to generate vex object
        #if self.size == 0:
        #    self.logger.warn("Refusing to analyse BBS of size 0")
        #    return
        self.bbs.clear()
        self.asm.clear()
        self.opcodes.clear()
        self.callees.clear()
        self.callers.clear()
        self.cfg = nx.DiGraph()
        self.data_refs = set()

        self.logger.debug("Analysing BasicBlockSequence...")
        
        #allow analysing from raw data without r2 and binary
        if len(self.data) != self.size:
            raise RuntimeError("Data basses to BasicBlockSequence did not matching it's size. {} - {}".format(len(self.data), self.size))
            #assert(r2_pipe_hdlr)
            #self.fill_bytes(r2_pipe_hdlr)

        assert(len(self.data) == self.size)
        self.logger.debug("Updating BBs and generating hashes")
        ##generate basic blopck sequence
        self.bbs_from_data()

        ###The following splits basicblock when pyVEX cannot decode full basic block
        i = 0
        while i < len(self.bbs):
            #self.logger.debug("Analysing basicblock {}/{} for function starting at  vaddr {}".format(i, len(self.bbs), self.vaddr))
            try:
                self.bbs[i].analyse(binary)
                self.asm        += self.bbs[i].asm
                self.opcodes    += self.bbs[i].opcodes
                #if 'callees' in self.bbs[i].vex:
                #    self.callees |= self.bbs[i].vex['callees'])

                i+=1

            except VEXLiftingError as e:
                offset = e.vex_size
                self.logger.warn("Patching VEX lifting error. New BB has offset: {}".format(offset))

                #skip 0 sized basicblocks being reported from VEX
                ##VEX cannot handle 'vmovups zmm0, zmmword ptr [rsi]',
                ##or 'prefetcht1 byte ptr [rsi + 0x40]',
                if offset == 0:
                    self.logger.warning("0 sized basicblock from VEX lifting")
                    self.asm        += self.bbs[i].asm
                    self.opcodes    += self.bbs[i].opcodes
                    i+=1
                    continue

                if offset == self.bbs[i].size:
                    print("error with max offset")
                    IPython.embed()
                    i+=1
                    continue

                bb = BasicBlock(self.config, 
                        data    = self.bbs[i].data[offset:], 
                        vaddr   = self.bbs[i].vaddr+offset,
                        size    = self.bbs[i].size - offset,
                        arch    = self.bbs[i].arch)

                self.bbs[i].size    = offset
                self.bbs[i].data    = self.bbs[i].data[:offset]
                #print('inserting extra bb')
                #IPython.embed()
                self.bbs.insert(i+1, bb)

            #pass on exception 
            except Exception as e: raise


        ##gen asm and opcode hashes for each bb
        self.gen_hashes()
        ##lift each bb to vex
        self.gen_vex()
        ##build cfg for BBS, needs to be done after generating VEX
        self.build_cfg()
        #tracl data xrefs
        self.data_refs = reduce(lambda x,y: x|y, map(lambda bb: bb.data_refs, self.bbs), set())

        #lva = LiveVariableAnalysis(self)
        #self.arguments       = lva.recover_function_arguments()
        #self.live_variables  = lva.recover_live_variables()

        self.callers = set(self.callers)
        self.callees = set(self.callees)

    def gen_hashes(self):
        """
            Maybe a true hash of data? Each BB is hashed, then we hash them all together
        """
        hash_obj = hashlib.sha256()
        opcode_hash_obj = hashlib.sha256()
        vaddr   = self.vaddr
        name    = self.name
        size    = self.size
        for bb in self.bbs:
            hash_obj.update( bb.hash )
            opcode_hash_obj.update( bb.opcode_hash )

        self.hash = binascii.unhexlify( hash_obj.hexdigest() )
        self.opcode_hash = binascii.unhexlify( opcode_hash_obj.hexdigest() )

    ###merge vex from each BB of a function into a VEX summary
    def gen_vex(self):
        #if all basic blocks are invalid, we might not have a basic block
        self.vex = {}
        self.vex['jumpkinds'] = []
        self.vex['constants'] = set([])
        self.vex['ninstructions'] = 0
        self.vex['ntemp_vars'] = 0
        self.vex['operations'] = []
        self.vex['callees'] = []
        
        for bb in self.bbs:
            if isinstance(bb, int):
                self.logger.debug("BasicBlock at addr {} with size ?".format( bb ))

                #ignore it
                assert(False and "BasicBlock is of type int (a vaddr, rather than class BasicBlock)")
            if not isinstance(bb, BasicBlock):
                self.logger.error("bb is not a basicblock instance!")
                IPython.embed()
                raise RuntimeError("bb is not a basicblock instance! {}".format(bb))

            #this basic blocks vex did not lift
            if not bb.vex:
                self.logger.warning("BasicBlock @ {} with size {} did not contain any VEX".format(bb.vaddr, bb.size))
                continue

            self.vex['jumpkinds'].append( bb.vex['jumpkind'] )
            self.vex['operations']   += bb.vex['operations']
            self.vex['constants'] |= bb.vex['constants']

            for key in ["ninstructions", "ntemp_vars"]:
                self.vex[key] += bb.vex[key]

            self.vex['callees'] += bb.vex['callees']

        ### squish jumpkinds into sum_jumpkinds
        self.vex['sum_jumpkinds']   = dict(collections.Counter(self.vex['jumpkinds']))
        self.vex['sum_operations']  = dict(collections.Counter(self.vex['operations']))


    def fill_bytes(self, r2_hdlr):
        """
            Get raw bytes for this BBS
        """
        assert(self.vaddr >= 0)
        if self.size == 0:
            self.data = b''
            return

        ##does not work with 0 size or negative vaddr
        self.data = bytes(json.loads(r2_hdlr.cmd("pxj {} @ {}".format(self.size, self.vaddr))))
        assert(len(self.data) == self.size)
        assert(isinstance(self.data, bytes))

    def build_cfg(self):
        """
            Builds a CFG from VEX BasicBlocks .exits property
            IDA BasicBlocks do not split on a call instruction!
            VEX needs to split on a call
        """
        #cfg is built from vex
        if not self.vex:
            return False

        ##check for valid bb addresses
        bb_nodes = set([])

        self.cfg = nx.DiGraph()
        non_const_counter = 0
        for bb in self.bbs:
            hex_start_vaddr = hex(bb.vaddr)
            self.cfg.add_node(hex_start_vaddr)
            bb_nodes.add(hex_start_vaddr)

            if not bb.vex:
                continue

            ##bb edges stored in exits
            for addr, jk in bb.exits:
                if addr == "non_const_exit":
                    # don't include return path in IntraProcedural CFG
                    continue
                    #too verbose
                    #self.logger.warning("Error, CFG has a non_const_exit!")
                    hex_addr = addr + "_" + str(non_const_counter)
                    non_const_counter += 1
                else:
                    ##all nodes are strings with addresses in hex prepended with 0x
                    hex_addr = hex(addr)

                """
                    Including the callee address might be incorrect but it gives us more 
                    information to compare CFG's. 
                    IDA doesn't split on Call, VEX must?
                """
                ##out of scope for this BBS's IntraProcedural CFG
                if jk == "Ijk_Call":
                    self.callees.add(hex_addr)
                    continue

                ##jump to address outside of this function
                if isinstance(addr, int):
                    if addr >= (self.vaddr + self.size) or addr < self.vaddr:
                        self.callees.add(hex_addr)
                        continue

                if jk == 'Ijk_SigFPE_IntDiv':
                    ##ignore potential FPE calls, calls next instruction after
                    #div, handler does not return (most cases)
                    self.logger.warning("CFG generation :: Skipping SigFPE_IntDiv jumpkind...")
                    continue

                ##Ijk_SigSEGV
                #skip

                self.cfg.add_edge(hex_start_vaddr, hex_addr, jumpkind=jk)

        for node in list(self.cfg.nodes()):
            ##const address
            if node[:2] == '0x':
                #const addr BB
                if node not in bb_nodes:
                    self.logger.warning("Removing node ({}) from CFG that we don't have a valid BB in BasicBlockSequence starting at vaddr {}".format(node, self.vaddr))
                    self.cfg.remove_node(node)

    @staticmethod
    def _num_diff(a, b):
        a, b = float(a), float(b)
        size_max = max( a, b )
        abs_diff = math.fabs(a - b)
        if size_max == 0:  # stop 0/0
            return 1.0
        else:
            sim = (size_max - abs_diff) / size_max
            assert( sim >= 0.0 and sim <= 1.0 )
            return sim




    #Get a measure of similarity between this BasicBlockSequence and another
    @staticmethod
    def dict_similarity(a, b, kern_iterations=10):
        """Compute the similarity of two BasicBlockSequences in dictionary form.

        :param a: The first BasicBlockSequence dict
        :param b: The second BasicBlockSequence dict
        :param kern_iterations: The number of iterations for teh WL graph kernel comparison
        :return: A similarity vector with each element a scrore between 0 and 1 based on the similarity between a and b for each feature.
        
        """
        sim = []
        #### Symbol size
        size_sim = BasicBlockSequence._num_diff(a['size'], b['size'])
        #print("size_sim: {}, a[size]: {}, b['size']: {}".format(size_sim, a[size], b['size']))
        sim.append(size_sim)

        #### Symbol hash
        if a['hash'] != b'' and b['hash'] != b'':
            hash_sim = 1.0 if a['hash'] == b['hash'] else 0.0
            sim.append(hash_sim)
        else:
            sim.append(0.0)

        #### Symbol opcode hash
        if a['opcode_hash'] != b'' and b['opcode_hash'] != b'':
            opcode_hash_sim = 1.0 if a['opcode_hash'] == b['opcode_hash'] else 0.0
            sim.append(opcode_hash_sim)
        else:
            sim.append(0.0)

        if a['vex'] and b['vex']:
            #### VEX Size       # sim[0]
            vex_ninstr_sim = BasicBlockSequence._num_diff(a['vex']['ninstructions'], b['vex']['ninstructions'])
            sim.append(vex_ninstr_sim)

            #### VEX number temporary variables
            #vex_nvars_sim = a['_num_diff'](a['vex']['ntemp_vars'], b['vex']['ntemp_vars'])
            #sim.append(vex_nvars_sim)

            #### Vex dictionay summary comparision kind
            ## sim[1:5]
            for kind in ["sum_jumpkinds", "temp_vars" ]:
                kind_a = set( a['vex'][kind].keys() )
                kind_b = set( b['vex'][kind].keys() )

                similar = len( kind_a.intersection(kind_b) )
                max_sim = max( len(kind_a), len(kind_b) )
                if max_sim == 0:
                    sim.append(1.0)
                else:
                    vex_sum_sim = float(similar) / max_sim
                    sim.append(vex_sum_sim)

                #build vector dot product between kinds and numbers
                kind_all = list(kind_a.union(kind_b))
                N = len(kind_all)
                a_kind_vec, b_kind_vec = np.zeros((N,), dtype=np.int), np.zeros((N,), dtype=np.int)
                for i in range(len(kind_all)):
                    if kind_all[i] in kind_a:
                        a_kind_vec[i] += a['vex'][kind][kind_all[i]]
                    if kind_all[i] in kind_b:
                        b_kind_vec[i] += float( b['vex'][kind][kind_all[i]] )

                dot = float( np.dot(a_kind_vec, b_kind_vec) )
                #magnitude = float( np.linalg.norm(a_kind_vec, ord=2) * np.linalg.norm(b_kind_vec, ord=2) )
                #10x quicker than np.linalg.norm
                magnitude = np.sqrt(a_kind_vec.dot(a_kind_vec)) * np.sqrt(b_kind_vec.dot(b_kind_vec))

                if magnitude == 0.0:
                    sim.append(1.0)
                else:
                    #### Floating point rounding errors!!!
                    #if abs(dot - magnitude) <= 0.000001:
                    #    dot = magnitude

                    if magnitude > 0.0:
                        #float point errors, dot can be bigger
                        magnitude = magnitude if magnitude >= dot else dot
                        vex_kind_sim = 1 - ( math.acos( dot / magnitude ) / (math.pi / 2) )
                    else:
                        vex_kind_sim = 0.0

                    sim.append( round(vex_kind_sim, 5) )

            #### VEX Order of jumpkinds
            ### sim[6]
            for i in range( min(len(a['vex']['jumpkinds']), len(b['vex']['jumpkinds']) ) ):
                if a['vex']['jumpkinds'][i] != b['vex']['jumpkinds'][i]:
                    break
            max_vex_order = max( len(a['vex']['jumpkinds']), len(b['vex']['jumpkinds']) )
            if max_vex_order > 1:
                vex_ordered_jks_sim = float(i + 1) / max_vex_order 
            else:
                vex_ordered_jks_sim = 0

            sim.append(vex_ordered_jks_sim)

            #### Vex constant matching
            #### sim[7]
            a['consts'] = set( list( map( lambda x: str(x[0]) + "_" + str(x[1]), a['vex']['constants'] ) ) )
            b['consts'] = set( list( map( lambda x: str(x[0]) + "_" + str(x[1]), b['vex']['constants'] ) ) )

            similar = len( a['consts'].intersection(b['consts']) )
            max_sim = max( len(a['consts']), len(b['consts']) )
            if max_sim == 0:
                sim.append(1.0)
            else:
                vex_consts_sim = float(similar) / max_sim
                sim.append(vex_consts_sim)

            
            #### sim[8:11]
            for ir_type in [ "statements", "operations", "expressions" ]:
                dot_prod = np.dot( a['vex'][ir_type], b['vex'][ir_type] )
                mag = np.sqrt(a['vex'][ir_type].dot(a['vex'][ir_type])) * np.sqrt(b['vex'][ir_type].dot(b['vex'][ir_type]))
                #domain of acos in 1 - -1, 0 is similar, 1 and -1 is not
                #no negative entries so domain should be between 0 - 1 
                #range is between -pi/2 +pi/2
                if mag > 0.0:
                    mag = mag if mag >= dot_prod else dot_prod
                    ir_type_sim = 1 - ( math.acos( dot_prod / mag ) / ( math.pi / 2 ) )
                else:
                    ir_type_sim = 0.0
                #round to 5 decimal places
                sim.append( round(ir_type_sim, 5) )

        #vex not implemented
        elif not a['vex'] and not b['vex']:
            sim += [1.0] * 10
        else:
            sim += [0.0] * 10

        #### CFG BBS number of callees
        callees_size_sim = BasicBlockSequence._num_diff( len(a['callees']), len(b['callees']) )
        sim.append(callees_size_sim)

        #### Number of basic blocks
        #Should be covered by VEX IR instructions, not helpful here

        #if both symbol shave more than 1 basic block i.e. > 1 edge on a cfg
        #if len(a['bbs']) > 1 and len(b['bbs']) > 1:
        if a['cfg'] and b['cfg']:
            aNumNodes = len(a['cfg'].nodes)
            bNumNodes = len(b['cfg'].nodes)

            #if both graphs have nodes and the biggest is less than 3 or they contain 75% of the number of nodes 
            if aNumNodes > 0 and bNumNodes > 0:
                big = max(aNumNodes, bNumNodes)
                small = min(aNumNodes, bNumNodes)
                rel_sim = float(small) / float(big)

                ##2 nodes connected
                if aNumNodes == 2 and bNumNodes == 2:
                    cfg_sim = 1.0

                elif rel_sim > 0.6:
                    #inter bbs cfg comparision using graph kernel
                    #try:
                    kern = GK_WL() 
                    cfg_sim = kern.compare( a['cfg'], b['cfg'], h=kern_iterations, node_label=False )
                    #except Exception as e:
                    #    logger.critical("Error! Exception raised in Graph kernel comparison!")
                    #    logger.critical(e)
                    #cfg_sim = 0.0 
                else:
                    cfg_sim = 0.0
            elif aNumNodes == 0 and bNumNodes == 0:
                cfg_sim = 1.0
            else:
                cfg_sim = 0.0

            sim.append(cfg_sim)

        elif a['cfg'] or b['cfg']:
            sim.append(0.0)
        else:
            sim.append(1.0)

        #### weightings from old JS implementation
        #[ 0.2, 1.0, 1.0, 0.5, 0.7, 0.3, 1, 1, 1, 1, 1, 0.8, 0.9, 0.9, 0.7, 0.3 ];
        
        #TODO: multiple vector by weightings
        #TODO: Automatically find the best weightings 
        #weightings = [ 0.7, 2.0, 1.5, 0.8, 0.5, 0.85, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.3, 0.85, 1.75 ]
        if len(sim) == 15:
            print(sim)
        w_sim = np.array( BasicBlockSequence.similarity_weightings ) * np.array( sim )

        return w_sim


    @staticmethod
    def static_fill_bytes(r2_hdlr, vaddr, size):
        """
            Get raw bytes for this BBS
        """
        assert(vaddr >= 0)
        if size == 0:
            #("Filling 0 bytes for BasicBlockSequence of 0 bytes")
            return b''

        """
            R2 API can return different type of data?????
        """
        bit_string = r2_hdlr.cmd("pB {} @ {}".format(str(size), str(vaddr)))
        if isinstance(bit_string, bytes): 
            bit_string = bit_string[:-1]
        elif isinstance(bit_string, str):
            pass
        else:
            raise RuntimeError("Error, unknown type of data returned from r2")

        if len(bit_string) == 1 + (8 * size):
            ##old r2 api
            bit_string = bit_string[:-1]
        elif len(bit_string) != 8 * size:

            print("Error getting function data from r2")
            IPython.embed()
            raise RuntimeError("Error getting function data from r2")

        byte_seq = list(classes.utils.chunks_of_size(bit_string, 8))
        assert(len(byte_seq) == size)
        int_seq = list(map(lambda x: int(x, 2), byte_seq))
        return bytes(int_seq)



class ConstantPropagation(BasicBlockSequence):
    """
        We need to identify constant values of registers in the functions mainly 
        for rsp, rbp
    """
    def __init__(self, config, bbs):
        classes.utils._desyl_init_class_(self, config)
        self.BBS = bbs
        self.eval_timeout = 5
        self.s = claripy.Solver(timeout=self.eval_timeout*1000)

        ##init state and function entry live vars
        self.state      = {}
        sys.setrecursionlimit(10000)

    #10 second timeout
    @timeout_decorator.timeout(5, use_signals=True)
    def evaluate_equal(self, a, b):
        return self.s.eval(a==b, 2)

    def merge_states(self, state, old_state):
        EQUAL = True
        for key, reg_value in list(state.items()):
            if key not in old_state:
                 EQUAL = False
                 continue
            old_reg_value = old_state[key]
            #if old_reg_value.concrete and reg_value.concrete:

            ###TOP covers all values, skip
            """
            NB: Depth can get very large >1000 for huge basicblocks

            We were freezing on a MD5 function that was made from 1 basicblock, 600 depth and converting to string 
            took a very long time > 5 mins
            Check depth==1 first
            """
            if reg_value.depth == 1 and 'TOP.state_merge' in str(reg_value):
                continue

            if old_reg_value.depth == 1 and 'TOP.state_merge' in str(old_reg_value):
                state[key] = old_state[key]
                continue

            #cond = old_reg_value == reg_value
            #b = cond.args
            b   = (None,)

            if old_reg_value.symbolic:
                b = (False,)
            elif reg_value.symbolic:
                b = (False,)
            else:
                b = self.evaluate_equal(old_reg_value, reg_value)
                #b = self.s.eval(old_reg_value==reg_value, 2)

            #IPython.embed()
            #b = old_reg_value == reg_value
            #if False in b.args:
            if True not in b:
                EQUAL = False
                state[key] = claripy.BVS("TOP.state_merge", state[key].size())
                #print("old_reg_value", old_reg_value)
                #print("reg_value", reg_value)
                #IPython.embed()
        return EQUAL, state
        """
        for key, reg_value in list(state.items()):
            if key not in old_state:
                print(key, "changed")
                print(reg_value)
                return False, state
            old_reg_value = old_state[key]
            b = old_reg_value == reg_value
            if False in b.args:
                ##replace with top, symbolic variable
                print(key, "changed")
                print(old_reg_value, reg_value)
                state
                return False, state
        return True, state
        """

    def propagate(self, see):
        """
        Recover live variables at entry and exit of each basicblock
        Resolved variables is a map of values for respoved register/memory and temp variables

        Topological sort basicblocks first!
        """
        if len(self.BBS.bbs) <= 0:
            return {}

        self.logger.debug("Propagating constants!")

        SEARCH_MODE = 'DFS'
        resolved        = {}
        bbs_vaddrs      = list(map(lambda x: hex(x.vaddr), self.BBS.bbs))

        ##add initial rsp, rbp according to resolved string format
        ##RIP alsways gets set in VEX IR
        def_ms  = see.default_machine_state()
        resolved["reg_bb{}_0_rsp".format(bbs_vaddrs[0])] = see.resolve_value_concrete(def_ms['rsp'], CONCRETE_ONLY=True)
        resolved["reg_bb{}_0_rbp".format(bbs_vaddrs[0])] = see.resolve_value_concrete(def_ms['rbp'], CONCRETE_ONLY=True)
        del def_ms

        try:
            ##topologically sorted BBS
            sorted_bbs = list(map(lambda x, l=bbs_vaddrs: l.index(x), nx.topological_sort(self.BBS.cfg)))
            SEARCH_MODE = 'BFS'
        except:
            ##cannot topologically sort cycles, default depth-first-search
            sorted_bbs = [0]
            ## NB: BFS was initially implemented, cannot handle multiple nested loops well!!
            SEARCH_MODE = 'DFS'

        worklist        = collections.deque(sorted_bbs)
        for i in range(len(self.BBS.bbs)):
            self.state[i] = {}, {}

        #default_keys = set(see.default_concrete_machine_state().keys())
        default_keys = set(see.default_machine_state().keys())

        #print(worklist)
        #IPython.embed()

        while len(worklist) > 0:
            #sys.stdout.write('.')
            #sys.stdout.flush()
            ##BFS search mode is needed for topologically sorted graph
            if SEARCH_MODE == 'BFS':
                node_ind    = worklist.popleft()
            elif SEARCH_MODE == 'DFS':
                node_ind    = worklist.pop()
            else:
                raise RuntimeError("Unknown search mode for constant propagation")

            node        = hex(self.BBS.bbs[node_ind].vaddr)
            bb = self.BBS.bbs[node_ind]
            """
                BUG: Remove all instances of node from the worklist otherwise infinite cycles from 2 loops can occour
            """
            while node_ind in worklist:
                worklist.remove(node_ind)

            if node not in self.BBS.cfg.nodes:
                IPython.embed()
                raise RuntimeError("Node is missing from CFG")

            #TODO: Optimize this, look at diffs from default machine state
            ## Do not track register states from other basicblocks 

            pre_machine_state, post_machine_state = self.state[node_ind]
            #see.machine_state = see.default_concrete_machine_state()
            see.machine_state = see.default_machine_state()
            see.machine_state.update(pre_machine_state)
            #see.machine_state   = copy.deepcopy(pre_machine_state)
            lv                  = LiveVariables(self.config, self.BBS.bbs[node_ind], set([]))
            res                 = lv.constant_propagation(see)

            ##string differences i.e. mem, registers
            temp_vars_re = re.compile(r'.*_t\d+')
            str_ref_diff = dict(filter(lambda x, f=temp_vars_re: isinstance(x[0], str) and not re.match(f, x[0]), res.items()))
            resolved.update(str_ref_diff)

            state_key_re = re.compile('reg_bb\d+_\d+_(.*)')
            modified_state_keys = set(map(lambda x,f=state_key_re: re.match(f, x).group(1), list(filter(lambda x,f=state_key_re: re.match(f, x), str_ref_diff))))
            memory_keys = set(filter(lambda x: 'mem_' in x, str_ref_diff))

            ##diff needs to be added to original state to propagate info
            mod_pre_machine_state = dict(map(lambda x, see=see: [ x, see.machine_state[x] ], memory_keys | modified_state_keys ))
            mod_post_machine_state = copy.deepcopy(pre_machine_state)
            mod_post_machine_state.update(mod_pre_machine_state)

            ##update resolved with basicblocks temporary variables
            tmp_ref_diff = dict(filter(lambda x, f=temp_vars_re: isinstance(x[0], str) and re.match(f, x[0]), res.items()))
            resolved.update(tmp_ref_diff)

            post_conditions_changed = False

            ##need to increment stack pointer if we are assumed function returns
            bbs_exits = self.BBS.bbs[node_ind].exits
            if len(bbs_exits) > 0:
                exits_vaddr, exits_jk = zip(*bbs_exits)
                if 'Ijk_Call' in exits_jk:
                        ###add machine address len to rsp
                        mod_post_machine_state['rsp'] += claripy.BVV(0x8, 64)
                        ##remove rsp from highest instruction in resolved
                        rsp_resolved    = dict(filter(lambda x: 'rsp' in x[0], str_ref_diff.items()))
                        max_inst, max_inst_key = -1, None
                        for rsp in rsp_resolved.keys():
                            m = re.match(r'reg_bb.*_(\d+)_rsp$', rsp)
                            assert(m)
                            inst_n = int(m.group(1))
                            if inst_n > max_inst:
                                max_inst = inst_n
                                max_inst_key = rsp

                        assert(max_inst_key)
                        del resolved[max_inst_key]

            equal, merged_state = self.merge_states(mod_post_machine_state, post_machine_state)
            if not equal:
                self.state[node_ind] = pre_machine_state, merged_state

                ##update postconditions of all predecessors 
                for start, end in self.BBS.cfg.out_edges(nbunch=node):
                    assert(start==node)
                    end_node_ind = bbs_vaddrs.index(end)
                    ##add to processing worklist
                    #self.logger.debug("adding BB {} ({}) to the worklist".format(end_node_ind, end))
                    if end_node_ind not in worklist:
                        worklist.append(end_node_ind)

                    ##merge state of postconditions, upper least bound
                    end_pre_machine_state, end_post_machine_state = self.state[end_node_ind]
                    self.state[end_node_ind] = copy.deepcopy(merged_state), end_post_machine_state

        return dict(filter(lambda x: isinstance(x[0], str), resolved.items()))


class TaintPropagation(BasicBlockSequence):
    """
        To find function arguments, find live variables from the entry
        point of the function, merge states using worklist algorithm

        forward algorithm
    """
    def __init__(self, config, bbs):
        classes.utils._desyl_init_class_(self, config)
        self.BBS = bbs

        ##init state and function entry live vars
        self.state      = {}

    def propagate(self, input_taints, resolved=None):
        """
        Propagate taint for each basicblock in function until we reach a fixed point
        Resolved variables is a map of values for respoved register/memory and temp variables
        """
        if len(self.BBS.bbs) <= 0:
            return set([])

        bbs_vaddrs      = list(map(lambda x: hex(x.vaddr), self.BBS.bbs))
        ##taints to apply to variable or basicblock
        ##indexed by basicblock
        taints_to_apply = {}

        ##if taint is of form reg_bb{}_reg
        ##apply taint at the start of this basicblock
        reg_bb_re = re.compile('reg_bb(\d+)_(.+)')
        for taint in set(input_taints):
            m = reg_bb_re.match(taint)
            if m:
                input_taints.remove(taint)
                bb_vaddr = int(m.group(1))
                if bb_vaddr in taints_to_apply:
                    taints_to_apply.add( m.group(2) )
                    continue
                taints_to_apply[ bb_vaddr ] = set([ m.group(2) ])

        """
        try:
            sorted_bbs = list(map(lambda x, l=bbs_vaddrs: l.index(x), nx.topological_sort(self.BBS.cfg)))
        except:
            sorted_bbs = [0]
        """
        sorted_bbs      = [0]
        ##if we apply taint in middle of function
        if len(taints_to_apply) > 0:
            sorted_bbs = list(range(len(self.BBS.bbs)))

        worklist        = collections.deque(sorted_bbs)

        self.state[0] = input_taints, set([])
        for i in range(1, len(self.BBS.bbs)):
            self.state[i] = set([]), set([])

        while len(worklist) > 0:
            node_ind    = worklist.pop()
            node_vaddr  = self.BBS.bbs[node_ind].vaddr
            node        = hex(node_vaddr)
            if node not in self.BBS.cfg.nodes:
                IPython.embed()
                raise RuntimeError("Node is missing from CFG")

            pre_tainted, post_tainted   = self.state[node_ind]
            in_tainted                  = copy.deepcopy(pre_tainted)

            ##apply taint from rules
            if node_vaddr in taints_to_apply:
                in_tainted |= taints_to_apply[node_vaddr]

            tt                          = TaintTracking(self.config, self.BBS.bbs[node_ind])
            out_tainted                 = tt.taint(in_tainted, resolved=resolved)

            ##remove temporary variables
            t_var_re        = re.compile(r't\d+')
            next_tainted    = set(filter(lambda x, f=t_var_re: not re.match(f, str(x)), out_tainted))

            post_conditions_changed = False
            if out_tainted != post_tainted:
                ##merge states
                post_conditions_changed = True
                self.state[node_ind] = pre_tainted, out_tainted

            if post_conditions_changed:
                ##update postconditions of all predecessors 
                for start, end in self.BBS.cfg.out_edges(nbunch=node):
                    assert(start==node)
                    end_node_ind = bbs_vaddrs.index(end)
                    ##add to processing worklist
                    #self.logger.debug("adding BB {} ({}) to the worklist".format(end_node_ind, end))
                    if end_node_ind not in worklist:
                        worklist.append(end_node_ind)

                    ##merge state of postconditions, upper least bound
                    end_pre_tainted, end_post_tainted = self.state[end_node_ind]

                    ##least upper bound
                    end_pre_tainted |= next_tainted
                    self.state[end_node_ind] = end_pre_tainted, end_post_tainted

        return self.state

    def latest_reg_name(self, reg, _bb_ind, resolved):
        """
        Finds last use of register in resolved, starting at current basic block index _bb_ind
        """
        highest = 0
        bb_ind = _bb_ind
        while highest == 0:
            reg_re = re.compile(r'reg_bb{}_(\d+)_{}'.format(self.BBS.bbs[bb_ind].vaddr, reg))
            for res in resolved.keys():
                m = re.match(reg_re, res)
                if m:
                    n = int(m.group(1))
                    if n > highest:
                        highest = n
            if highest == 0:
                bb_ind -= 1

            if bb_ind < 0:
                print("Error, invalid bb_ind for register `{}`".format(reg))
                IPython.embed()
                raise RuntimeError("Failed to retieve", reg)

        return 'reg_bb{}_{}_{}'.format(self.BBS.bbs[bb_ind].vaddr, highest, reg)

    def analyse(self, binary, func_args, resolved=None):
        """
            Produce information from taint analysis

            1) Generate tainted flows
        """
        t_state = self.propagate(set(func_args), resolved=resolved)
        flows   = []
        rsp_re  = re.compile(r'reg_bb\d+_\d+_rsp')
        mem_re  = re.compile(r'mem_0x(.*)')
        resolved_rsps = dict(filter(lambda x, f=rsp_re: re.match(f, x[0]), resolved.items())) 

        for i, bb in enumerate(self.BBS.bbs):
            for vaddr, jk in bb.exits:
                if jk == 'Ijk_Call':
                   ##check if function arguments to other functions are tainted
                    callee_func_args = t_state[i][1] & set(['rsi', 'rdi', 'rdx', 'rcx', 'r8', 'r9'])
                    if resolved:
                        ##get current stack pointer
                        latest_rsp = self.latest_reg_name('rsp', i, resolved_rsps)
                        if resolved[latest_rsp]:
                            stack_start = resolved[latest_rsp]
                            #print("Stack for callee function starts at", hex(stack_start))
                            mem_tainted = set(filter(lambda x, f=mem_re: re.match(f, x), t_state[i][1]))
                            for mem in mem_tainted:
                                m = re.match(mem_re, mem)
                                if m:
                                    mem_vaddr = int(m.group(1), 16)
                                    #print(hex(stack_start), hex(mem_vaddr))
                                    ##TODO check tainted variable on the stack is actually used by the callee function
                                    #IPython.embed()
                                    if mem_vaddr > stack_start:
                                        callee_func_args.add(mem)

                    if not isinstance(vaddr, int):
                        self.logger.info("Non const call in taint tracking flows")
                        continue
                    for func_callee in binary.vaddr_to_name_tree.at(vaddr):
                        #print("Append flow", func_callee.data)
                        flows.append( (func_callee.data, callee_func_args) )
                elif jk == 'Ijk_Ret':
                    ret_args = t_state[i][1] & set(['rax', 'xmm0', 'ymm0'])
                    flows.append(('__FUNC_RET__', ret_args))

        return flows

    def basicblock_analyse(self, binary, func_args, resolved=None):
        """
            Produce information from taint analysis on basicblock level

            1) Generate tainted flows
        """
        t_state = self.propagate(set(func_args), resolved=resolved)
        flows   = []
        rsp_re  = re.compile(r'reg_bb\d+_\d+_rsp')
        mem_re  = re.compile(r'mem_0x(.*)')
        resolved_rsps = dict(filter(lambda x, f=rsp_re: re.match(f, x[0]), resolved.items())) 

        for i, bb in enumerate(self.BBS.bbs):
            for vaddr, jk in bb.exits:
                if jk == 'Ijk_Call':
                   ##check if function arguments to other functions are tainted
                    callee_func_args = t_state[i][1] & set(['rsi', 'rdi', 'rdx', 'rcx', 'r8', 'r9'])
                    if resolved:
                        ##get current stack pointer
                        latest_rsp = self.latest_reg_name('rsp', i, resolved_rsps)
                        if resolved[latest_rsp]:
                            stack_start = resolved[latest_rsp]
                            #print("Stack for callee function starts at", hex(stack_start))
                            mem_tainted = set(filter(lambda x, f=mem_re: re.match(f, x), t_state[i][1]))
                            for mem in mem_tainted:
                                m = re.match(mem_re, mem)
                                if m:
                                    mem_vaddr = int(m.group(1), 16)
                                    #print(hex(stack_start), hex(mem_vaddr))
                                    ##TODO check tainted variable on the stack is actually used by the callee function
                                    #IPython.embed()
                                    if mem_vaddr > stack_start:
                                        callee_func_args.add(mem)

                    if not isinstance(vaddr, int):
                        self.logger.info("Non const call in taint tracking flows")
                        continue
                    for func_callee in binary.vaddr_to_name_tree.at(vaddr):
                        #print("Append flow", func_callee.data)
                        flows.append( (bb.vaddr, vaddr, callee_func_args) )
                elif jk == 'Ijk_Ret':
                    ret_args = t_state[i][1] & set(['rax', 'xmm0', 'ymm0'])
                    flows.append((bb.vaddr, '__FUNC_RET__', ret_args))

                else:
                    if len(t_state[i][1]) > 0:
                        ##pass taint to vaddr
                        flows.append((bb.vaddr, vaddr, t_state[i][1]))

        return flows

class LiveVariableAnalysis(BasicBlockSequence):
    """
        To find function arguments, find live variables from the entry
        point of the function, merge states using worklist algorithm
    """
    def __init__(self, config, bbs):
        classes.utils._desyl_init_class_(self, config)

        self.BBS = bbs
        ##init state and function entry live vars
        self.state      = {}

    def all_function_variables(self, see=None):
        if see:
            tracked_machine_regs_keys = set(['rsp', 'rip', 'rbp'])
            machine_regs = { k: copy.deepcopy(see.machine_state[k]) for k in tracked_machine_regs_keys }

            all_vars = []
            for bb in self.BBS.bbs:
                machine_regs['rip'] = bb.vaddr
                lv = LiveVariables(self.config, bb)
                post_computed_vars = lv.resolve_memory_addresses(see)
                ##post_computed vars holds register values at end of basicblock, 
                ##gen all variables and pass in initial reg values
                pre_computed_vars = copy.deepcopy(post_computed_vars)
                pre_computed_vars.update(machine_regs)


                all_vars.append(
                        lv.gen_all_variables(resolved_variables=pre_computed_vars)
                )
                #IPython.embed()
                #for k in set(machine_regs.keys()):
                #    machine_regs[k] = post_computed_vars[k]
        else:
            all_vars = list(map(lambda x, f=LiveVariables, c=self.config: f(c, x).gen_all_variables(), self.bbs))

        return reduce(lambda x, y: x.union(y), all_vars, set([]))

    def recover_live_variables(self, resolved_variables=None):
        """
        Recover live variables at entry and exit of each basicblock
        Resolved variables is a map of values for respoved register/memory and temp variables

        NB: RSP is always live for a standard function epilogue because ret restore teh previous rsp from this value
        """
        if len(self.BBS.bbs) <= 0:
            return set([])

        ##init state and function entry live vars
        self.state      = {}

        #start with terminating basicblocks
        leaf_nodes = [x for x in self.BBS.cfg.nodes() if self.BBS.cfg.out_degree(x)==0]
        if(len(leaf_nodes) <= 0):
            self.logger.warning("No leaf nodes, assuming last BB")
            leaf_nodes = [ hex(self.BBS.bbs[-1].vaddr) ]
            #return set([])
            ##need to terminate CFG on calling exit
            #IPython.embed()
            #raise RuntimeError("Error, no leaf nodes")

        bbs_vaddrs = list(map(lambda x: hex(x.vaddr), self.BBS.bbs))

        ##lv exit for last block and is the empty set
        #store the value of registers and tmp variables throughout the execution

        for i in range(len(self.BBS.bbs)):
            self.state[i] = set([]), set([])

        ##list of nodes that need computing
        worklist            = collections.deque()
        for x in leaf_nodes:
            bbs_index = bbs_vaddrs.index(x)
            worklist.append(bbs_index)

        while len(worklist) > 0:
            node_ind    = worklist.pop()
            node        = hex(self.BBS.bbs[node_ind].vaddr)
            if node not in self.BBS.cfg.nodes:
                IPython.embed()
                raise RuntimeError("Node is missing from CFG")

            lv_entry, lv_exit = self.state[node_ind]
            lv = LiveVariables(self.config, self.BBS.bbs[node_ind], lv_exit)

            V = lv.live_variables(resolved_variables=resolved_variables)

            pre_conditions_changed = False

            if node_ind in self.state.keys():
                if V != lv_entry:
                    ##merge states
                    pre_conditions_changed = True
                    self.state[node_ind] = copy.deepcopy(V), lv_exit
            else:
                pre_conditions_changed = True
                ##add state
                self.state[node_ind] = copy.deepcopy(V), lv_exit

            if pre_conditions_changed:
                ##update postconditions of all predecessors 
                for start, end in self.BBS.cfg.in_edges(nbunch=node):
                    assert(end==node)
                    start_node_ind = bbs_vaddrs.index(start)
                    ##add to processing worklist
                    #self.logger.debug("adding BB {} ({}) to the worklist".format(start_node_ind, start))
                    if start_node_ind not in worklist:
                        worklist.append(start_node_ind)

                    ##merge state of postconditions, upper least bound
                    start_lv_entry, start_lv_exit = self.state[start_node_ind]
                    new_lv_exit = start_lv_exit.union(copy.deepcopy(V))
                    self.state[start_node_ind] = start_lv_entry, new_lv_exit

        lv_entry_func_start, lv_exit_func_start = self.state[0]
        return lv_entry_func_start

    def recover_function_arguments(self, resolved_variables=None, stack_start=None):
        live_vars   = self.recover_live_variables(resolved_variables=resolved_variables)
        fp_args     = set(['ymm' + str(x) for x in range(8)])
        rg_args     = set(['rsi', 'rdi', 'rdx', 'rcx', 'r8', 'r9'])
        reg_args    = live_vars.intersection(fp_args | rg_args)
        mem_args    = set([])

        if not resolved_variables or not stack_start:
            return reg_args

        reg_mem_concrete = re.compile(r'mem_0x([0-9a-fA-F]+)')
        for var in live_vars:
            m = re.match(reg_mem_concrete, var)
            if not m:
                continue

            if int(m.group(1), 16) > stack_start:
                mem_args.add(var)

        return reg_args | mem_args

    def analyse(self, see):
        #perform constant propagation
        cpa         = ConstantPropagation(self.config, self.BBS)
        self.logger.info("Performing Constant Propagation")
        resolved    = cpa.propagate(see=see)

        self.logger.info("Performing Live Variable Analysis")
        live        = self.recover_live_variables(resolved_variables=resolved)



        #SYS V ABI calling convention
        fp_args     = set(['ymm' + str(x) for x in range(8)]) | set(['xmm' + str(x) for x in range(8)])
        rg_args     = set(['rsi', 'rdi', 'rdx', 'rcx', 'r8', 'r9'])
        live_args        = live.intersection(fp_args | rg_args)
        live_heap        = set([])
        live_locals = set([])
        live_thread_local_storage = set([])
        local_stack_bytes = 0
        num_locals = 0

        reg_mem_concrete = re.compile(r'mem_0x([0-9a-fA-F]+)')
        for var in live:
            m = re.match(reg_mem_concrete, var)
            if not m:
                continue

            vaddr = int(m.group(1), 16)
            if vaddr <= see.stack_start and vaddr > see.stack_end:
                ##live local stack arguments? YES this is correct. I think it is
                #from stack_chck_fail canary
                ## OR When varaibels are created passed by reference e.g. 
                ### it is actually reading the stack memory and placing it back
                ### on the stack
                """
                    f(){
                        local *a;
                        fill_data(&a);   <=== cannot detect this
                        *a = 3;     // a is being dereferenced first, so reads value of a 
                    }
                """
                ##The value of stack_start will be live from the start of a function and this is to be expected!
                ## this is because ret is reading from this value and putting the value in rsp
                live_locals.add(var)
            elif vaddr > see.stack_start and vaddr < see.fs_default:
                ##arguments passe don the stack
                live_args.add(var)
            elif vaddr < see.stack_end:
                live_heap.add(var)
            elif vaddr > see.fs_default:
                live_thread_local_storage.add(var)
            else:
                self.logger.error("wierd stuff going on, non standard SYSV ABI.")
                self.logger.error("Function is accessing uninitialised local stack var?")
                self.logger.error(var)

        ##need to check exits, call will decrment stack by 8 bytes, rsp consts that are the reuslt
        #of calls are removed
        resolved['__DESYL__rsp_start'] = see.stack_start
        rsps = dict(filter(lambda x: 'rsp' in x[0] and x[1], resolved.items()))
        min_rsp = min(dict(filter(lambda x: x[1] >= see.stack_end, rsps.items())).values())
        rsp_diff = see.stack_start - min_rsp
        if rsp_diff >= (3 * 8): ##3 64 bit, rbp, rip, rsp
            local_stack_bytes = (rsp_diff - (3*8))

        num_locals = local_stack_bytes // 8

        return live_args, live_heap, live_thread_local_storage, live_locals, local_stack_bytes, num_locals, resolved
