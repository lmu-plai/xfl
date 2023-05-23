import context
import sys
import classes.config
import classes.binary
import classes.symbol
import classes.database
import classes.utils
import random
import os
import logging
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import IPython

from asm_embed.util import AsmInstruction, write_trace_to_file

ARCH = CS_ARCH_X86
MODE = CS_MODE_64

md = Cs(ARCH, MODE)
def get_capstone_insn(code, offset):
    return list(md.disasm(code, offset))

"""class Bbs_dict(dict):
    def __getitem__(self, key):
        return super().__getitem__(str(hex(key)))
"""

class Asm2Vec():

    def __init__(self, config, outpath, num_rand_wlk=3):
        classes.utils._desyl_init_class_(self, config)
        self.num_rand_wlk = num_rand_wlk
        self.outpath = outpath



    def load_binary(self, path, filter_func=None):
        ###load a binary? maybe more?
        self.config.logger.warning("Starting analysing")
        b = classes.binary.Binary(self.config, path=path)
        b.analyse()
        if filter_func is None:
            filter_func = lambda x: True

        for s in list(filter(lambda x : x.binding == 'GLOBAL', b.symbols)):
            if not filter_func(s):
                continue
            p = os.path.join(self.outpath, 'functions', b.name + '::' + s.name)
            #print(p)
            if not os.path.exists(p):
                self.config.logger.debug("Creating directory {}".format(p))
                try:
                    os.makedirs(p)
                except OSError:
                    self.config.logger.error("OSError happened while creating {}".format(p))
                    continue
            ##functions in the binaries .text
            start_addr = s.vaddr

            if len(s.bbs) == 0:
                # This actually happens
                self.config.logger.warning("Symbol {} has no basic blocks!".format(s.name))
                continue

            bbs_dict = dict([(bb.vaddr, bb) for bb in s.bbs])
            #print(bbs_dict)
            #print(start_addr)
            start_block = bbs_dict[start_addr]
            '''for bb in s.bbs:
                print(bb.asm)
                print(bb.exits)'''

            for j in range(self.num_rand_wlk):
                l = list(md.disasm(start_block.data, start_block.vaddr))
                #print(start_block.data)
                #print(l)
                trace = []

                
                trace.extend(map(AsmInstruction.from_capstone_insn, l))
                #print("Trace at start")
                #print(trace)
                bb_trace = [start_block]
            
                visited_nodes = set()
                visited_nodes.add(start_block.vaddr)

                while True:
                    successors = bb_trace[-1].exits
                    if len(successors) == 0:
                        self.config.logger.warning("No successors found for {} in {}:{}".format(trace[-1].vaddr, b.name, s.name))
                        break
                        
                    elif len(successors) == 1:
                        self.config.logger.info("Case 1")
                        if successors[0][1] == 'Ijk_Ret':
                            self.config.logger.info("- Case 1a: Ijk_Ret")
                            #print("Ijk_Ret:")
                            #print(trace)
                            # Function returns here, end trace
                            break
                        elif successors[0][1] == 'Ijk_Boring':
                            self.config.logger.info("- Case 1b: Ijk_Boring")
                            #print("Case Ijk_Boring")
                            # Only successor is a basic block
                            if successors[0][0] in visited_nodes:
                                break
                            if successors[0][0] == 'non_const_exit':
                                # Since we have no information, we must end the trace here.
                                break
                            try:
                                bb_trace.append(bbs_dict[successors[0][0]])
                            except:
                                # Jumping to an address outside of the function (happens in specialized function calls)
                                l = list(b.vaddr_to_name_tree.at(successors[0][0]))
                                if len(l) > 1:
                                    # Overlapping functions here, we won't do anything
                                    break
                                if len(l) == 0:
                                    break
                                #assert(len(l)) == 1
                                # Jumps outside of the function, we will just handle it as a function call and replace the jump target
                                trace[-1] = trace[-1].replace_call_target(l[0].data)
                                break
                            visited_nodes.add(successors[0][0])
                            trace.extend(map(AsmInstruction.from_capstone_insn, get_capstone_insn(bb_trace[-1].data, successors[0][0])))
                        elif successors[0][1] == 'Ijk_SigTRAP':
                            self.config.logger.warning("- Case 1c: Ijk_SigTRAP")
                            break
                        else:
                            self.config.error(" Unknown Ijk: ".format(successors[0][1]))
                    elif len(successors) == 2:
                        self.config.logger.info("Case 2")
                        s1 = successors[0]
                        s2 = successors[1]
                        if s2[0] in visited_nodes:
                            break
                        if s1[1] == 'Ijk_Call' and s2[1] == 'Ijk_AssumedRet':
                            self.config.logger.info(" Case 2a: Ijk_Call and Ijk_AssumedRet")
                            #print("Case Ijk_Call and Ijk_AssumedRet:")
                            #print(trace)
                            # This block calls s1 and then returns to s2
                            # First, replace the call target of last instruction in trace with name of s1 target
                            try: 
                                call_target = b.get_symbol(key='vaddr', value=s1[0]).name
                            except:
                                # Can't find a symbol for this address
                                try:
                                    #IPython.embed()
                                    call_target = list(b.vaddr_to_name_tree.at(s1[0]))[0].data
                                except:
                                    # Can't find anything for this address; won't replace anything
                                    call_target = None
                                #IPython.embed()
                            if call_target is not None:
                                self.config.logger.debug("Replacing call to {} with {}".format(s1[0], call_target))
                                trace[-1] = trace[-1].replace_call_target(call_target)
                            # Second, next block is s2
                            try:
                                bb_trace.append(bbs_dict[s2[0]])
                            except:
                                # If basic block not in this symbol, the call is most likely not returning
                                # So we end the trace here
                                break
                            visited_nodes.add(s2[0])
                            trace.extend(map(AsmInstruction.from_capstone_insn, get_capstone_insn(bb_trace[-1].data, s2[0])))
                        elif s1[1] == 'Ijk_Boring' and s2[1] == 'Ijk_Boring':
                            self.config.logger.info("- Case 2b: Both Ijk_Boring")
                            #print("Case both are Ijk_Boring")
                            # Both successors are basic blocks, randomly choose one
                            succ = random.choice(successors)
                            if succ[0] in visited_nodes:
                                break
                            try:
                                bb_trace.append(bbs_dict[succ[0]])
                            except:
                                # Jumping outside of our function, end the trace here, but replace call target
                                try:
                                    call_target = b.get_symbol(key='vaddr', value=succ[0]).name
                                except:
                                    call_target = list(b.vaddr_to_name_tree.at(succ[0]))[0].data
                                # due to a bug, 'repe' instructions are handled as exits, so we disable replacing
                                # call target for now
                                #trace[-1] = trace[-1].replace_call_target(call_target)
                                break
                            visited_nodes.add(succ[0])
                            trace.extend(map(AsmInstruction.from_capstone_insn, get_capstone_insn(bb_trace[-1].data, succ[0])))

                        else:
                            self.config.logger.error(" len(successors) == 2, but unknown case")
                            break
                    elif len(successors) > 2:
                        self.config.logger.error("len(successors) > 2")
                        self.config.logger.error("Successors: {}".format(successors))
                        break
                write_trace_to_file(os.path.join(p, '{:04d}'.format(j)), trace)

"""
            ###naviagte the networkx CFG or using the list of BasicBlocks and their 
            #exits

            ##funcs control flow graph as networkx graph
            #s.cfg

            #s.asm
            #s.opcodes
            #bb.asm

            ##first basicblock is at the start of the function
            ##for each basicblock in function
            for basicblock in s.bbs:
                ##for each exit in this basicblock
                for exit_vaddr, jumpkind in basicblock.exits:
                    ##for each function that corresponds to this address
                    for function in b.vaddr_to_name_tree.at(exit_vaddr):
                        ###type intervaltree range
                        name = function.data"""


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: asm2vec.py [configfile] [binary] [outpath]")
        sys.exit(-1)
    config = classes.config.Config(sys.argv[1])
    config.logger.setLevel('WARNING')
    asm2vec = Asm2Vec(config, sys.argv[3])

    ##do stuff here
    asm2vec.load_binary(sys.argv[2])
