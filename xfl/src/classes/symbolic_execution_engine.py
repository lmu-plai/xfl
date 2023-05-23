import os, sys, copy
import pyvex, archinfo
from archinfo.arch_amd64 import ArchAMD64
import math
import re
import logging
import IPython
import timeout_decorator
import claripy
import collections
import functools

import context
from classes.config import Config
from classes.basicblock import BasicBlock, LiveVariables
import classes.utils

CARRY_FLAG_BIT      = 0
PARITY_FLAG_BIT     = 2
ADJUST_FLAG_BIT     = 4
ZERO_FLAG_BIT       = 6
SIGN_FLAG_BIT       = 7
DIRECTION_FLAG_BIT  = 10
OVERFLOW_FLAG_BIT   = 11

class ExecutionState():
    def __init__(self, se2):
        self.machine_state = copy.deepcopy(se2.machine_state)
        self.tainted = copy.deepcopy(se2.tainted)


class SymbolicExecutionEngine():
    def __init__(self, config, binary):
        classes.utils._desyl_init_class_(self, config)
        ##2500 millisecond timeout
        self.solver = claripy.solvers.Solver(timeout=3500)
        self.binary = binary
        self.execution_states = {}
        ##taint user input/memory allocation
        self.taint_rets_from = set([#'malloc', 'kmalloc', 'calloc', 'realloc'
            #'read', 'fread'
            #'gets', 'fgets', 'fgetc', 'getchar'
            ])

        self.taint_args_to = set([
                #('free', 'rdi')
        ])

        self.stack_size     = 2048
        self.stack_base     = 0x7ffffffffff0000
        self.stack_start    = self.stack_base - self.stack_size
        self.stack_end      = 0x700000000000000
        self.fs_default     = 0xa00000000000000
        self.gs_default     = 0xd00000000000000

        self.clear_machine_state()

        #store data from loading binary in a common shared fixed memory bank
        #updates to this memory region are copied on use to machine_state
        self.fixed_memory = {}

        ###load data sections into memory
        ###memory is moddeled per byte
        for name, vaddr_start, vaddr_end, size, contents in self.binary.sections:
            self.logger.info("Filling memory with data from {} section".format(name))
            for i in range(size):
                self.fixed_memory['m_' + hex(vaddr_start + i)] = claripy.BVV(contents[i], 8)

        if binary.arch != 'x86_64':
            raise RuntimeError("Error, getting arguments for {} is not currently supported. Only x86_64.".formation(binary.arch))

    def __getstate__(self):
        classes.utils._desyl_deinit_class_(self)
        return self.__dict__

    def __setstate__(self, state):
        self.__dict__ = state
        classes.utils._desyl_init_class_(self, Config())



    def clear_machine_state(self):
        self.machine_state      = self.default_machine_state()
        self.tainted            = copy.deepcopy(set([]))
        self.execution_states   = {}

    def restore_machine_state(self, state):
        self.machine_state  = copy.deepcopy(state.machine_state)
        self.tainted        = copy.deepcopy(state.tainted)


    def __clear_bb_temp_vars(self):
        """
        Remove temporray variable from VEX IR created per basic block
        """
        ##maintain, register, memory prefixed with 'm_'.
        ##throw away temporary variables
        ##temporary variables are creates as integers
        self.machine_state = dict(filter(lambda x: isinstance(x[0], str), self.machine_state.items()))

        ##only taint named registers iter-basicblocks
        ## tainted == live registers from a basic block
        self.tainted = set(filter(lambda x: isinstance(x, str), self.tainted))

    def resolve_expr_concrete(self, expr):
        """
        Find a concrete value for expression
        Returns none otherwise
        """
        if isinstance(expr, pyvex.expr.Const):
            vaddr = expr.con.value
            return vaddr

        if isinstance(expr, pyvex.const.IRConst):
            return expr.value

        if expr.tmp in self.machine_state:
            ##if value is concrete
            addr_target = self.machine_state[ expr.tmp ]
            if addr_target.concrete:
                solved = self.solver.eval( addr_target, 1)
                return solved[0]
            else:
                #timeout symbolic resolve
                #card = self._get_cardinality(addr_target)
                #if not card:
                #    return None

                try:
                    solved = self.solver.eval(addr_target, 1)
                    for val in solved:
                        return val

                except claripy.errors.ClaripyFrontendError as e:
                    return None
        return None

    def resolve_value_concrete(self, value, CONCRETE_ONLY=False):
        if CONCRETE_ONLY:
            if value.symbolic:
                return None
        try:
            solved = self.solver.eval(value, 1)
            return solved[0]
        except Exception as e:
            self.logger.error(e)
        return None

    def execute_all_symbols_symbolic_args(self):
        """
            Execute a list of symbols
        """
        for s in self.binary.symbols:
            self.clear_machine_state()
            yield self.execute_function(s, s.vex['arguments'])

    def taint_all_functions(self):
        """
            Execute a list of symbols
        """
        for s in self.binary.symbols:
            self.clear_machine_state()
            yield self.execute_function(s)

    #5 min timeout per function
    #@timeout_decorator.timeout(300, use_signals=False)
    def execute_function(self, bb_seq, orig_tainted=set([])):
        ##TODO VEX lifting misses cuts basic blocks short!
        ##fixed in analysis but not here

        ##execute a sequence of basic blocks, return all flows from tainted in current machine state
        flows = set([])
        self.clear_machine_state()

        self.logger.debug("Executing function {}".format(bb_seq.name))

        #empty function
        if len(bb_seq.bbs) == 0:
            return flows

        self.tainted = self.tainted.union(orig_tainted)

        #two lists with index of addrs and addrs
        bb_inds, bb_addrs = zip(* list(enumerate(list(map(lambda x: x.vaddr, bb_seq.bbs)))) )

        BB_VADDRS = list(map(lambda x: x.vaddr, bb_seq.bbs))
        BB_IND, MAX_BB = 0, len(bb_seq.bbs)
        while True:
            ##clears temp variable in machine state created by basic block
            self.__clear_bb_temp_vars()

            #print("BB_IND: {}, MAX_BB: {}, CACHE_SIZE: {}".format(BB_IND, MAX_BB, len(BB_COV_CACHE)))
            #IPython.embed()

            #if we have already exeuted this bb, skip
            if BB_IND in self.execution_states.keys():
                try:
                    BB_IND, state = next(self.bfs_emit_state(bb_seq, BB_VADDRS))
                    self.restore_machine_state(state)
                except StopIteration:
                    ##out of bbs to process
                    break
                    pass

            bb = bb_seq.bbs[BB_IND]

            if not isinstance(bb, BasicBlock):
                raise RuntimeError("Error! bb is not a baisc block - {}".format(bb))

            if not bb.irsb:
                self.logger.warning("Error, invalid IRSB for basicblock")
                """
                    case seen where invalid offset results in corrcet decoding
                    of x86 instructions. Simply increment BB, otherwise need to
                    decompile again
                    ______
                    |cond|
                    |jnz |
                    ------
                    |   |
                    lock ----
                    |       |
                    -------------
                    |  xchngcmp |
                    -------------
                """
                self.execution_states[BB_IND] = ExecutionState(self)
                BB_IND+=1
                ##this was patched in CFG generation to have overlapping
                #basicblocks
                raise RuntiomeError("Error, invalid IRSB for basicblock")
                continue

            self.execute_basicblock(bb)
            ##save execution in state manager
            self.execution_states[BB_IND] = ExecutionState(self)

            if type(bb.irsb) == type(None):
                print("???none type")
                IPython.embed()

            ##update set of exits
            call_vaddr = self.resolve_expr_concrete(bb.irsb.next)
            if not isinstance(call_vaddr, int):
                #cannot determine call vaddr
                ## just move on sequentially
                self.logger.warning("Error following basicblock sequence! Symbolic address!")
                continue
            bb_seq.bbs[BB_IND].exits.append((int(call_vaddr), bb.irsb.jumpkind))

            #Happens for buggy VEX lifting
            if len(bb.irsb.statements) > 0:
                if isinstance(bb.irsb.statements[-1], pyvex.stmt.Exit):
                    alt_vaddr   = self.resolve_expr_concrete(bb.irsb.next)
                    jk          = bb.irsb.statements[-1].jumpkind
                    if alt_vaddr:
                        bb_seq.bbs[BB_IND].exits.append((int(alt_vaddr), jk))

            #return basicblock
            if bb.irsb.jumpkind == 'Ijk_Ret':
                tainted_func_args = set([ 'rax', 'xmm0', 'xmm1' ]).intersection(self.machine_state)
                ##return flow
                for arg in tainted_func_args:
                    flows.add( ( bb_seq.name, "__desyl_ret__" + arg ) )

                #returning from this function, bye
                #return flows
                continue

            ##skip fixed jumps inside function
            if bb.irsb.jumpkind == 'Ijk_Boring' or bb.irsb.jumpkind == 'Ijk_Call':

                end_names = list( self.binary.vaddr_to_name_tree.at( call_vaddr ) )
                real_end_names = list( self.binary.vaddr_to_real_name_tree.at( call_vaddr ) )
                if(len(end_names) == 0):
                    self.logger.error("ERROR, call reference not found!! {} :: {} -> {}".format(bb_seq.name, hex(bb.vaddr), hex(call_vaddr)))
                    FUNC_NAME = "DESYL_UNKNOWN_FUNC__{}".format(call_vaddr)
                    REAL_FUNC_NAME = FUNC_NAME
                else:
                    FUNC_NAME       = end_names[0].data
                    REAL_FUNC_NAME  = real_end_names[0].data
                    call_args = self.binary.get_func_args(REAL_FUNC_NAME,
                            real_name=True)

                    ##don't include intraprocedural jumps unless then are with
                    ##call jumpkind
                    if FUNC_NAME != bb_seq.name or bb.irsb.jumpkind == 'Ijk_Call':
                        for arg in call_args:
                            if arg in self.tainted:
                                flows.add( ( FUNC_NAME, arg ) )

                if bb.irsb.jumpkind == 'Ijk_Call': 
                    ##x86_64 return value from call site taints
                    ##assume function returns a value
                    ##fake symbolic return value
                    self._set_register_value('rax', claripy.BVS("{}_RET".format(REAL_FUNC_NAME), 64))
                    self._set_register_value('ymm0', claripy.BVS("{}_RET".format(REAL_FUNC_NAME), 256))
                    self._set_register_value('ymm1', claripy.BVS("{}_RET".format(REAL_FUNC_NAME), 256))
                    if FUNC_NAME in self.taint_rets_from:
                        self.logger.info("Adding taint from return value of {}".format(FUNC_NAME))
                        self.tainted.add('rax')
                        self.tainted.add('ymm0')
                        self.tainted.add('ymm1')

                self._enforce_register_sizes()

        return flows

    def bfs_emit_state(self, bb_seq, BB_VADDRS):
        """
            Beadth First Search of BasicBlocks
            generates a list of basicblocks and execution states for each
        """

        #TODO: ensure this algorithm is efficient!
        while True:
            ###size of states may change outside of this generator
            REFRESH = False
            for bb_index, state in self.execution_states.items():
                for exit_addr, jk in bb_seq.bbs[bb_index].exits:
                    #print("BB index: {}".format(exit_addr))
                    if isinstance(exit_addr, str):
                        continue

                    if jk in set(['Ijk_Call', 'Ijk_Ret']):
                        continue

                    if exit_addr not in BB_VADDRS:
                        self.logger.debug("Address {} is not inside this function ({}) from bb {}".format(
                            exit_addr, bb_seq.real_name, bb_seq.bbs[bb_index].vaddr))
                        continue
                    vaddr_ind = BB_VADDRS.index(exit_addr)
                    if vaddr_ind >= 0 and  vaddr_ind not in self.execution_states.keys():
                        REFRESH = True
                        yield vaddr_ind, state
                        break
                if REFRESH:
                    break
            if not REFRESH:
                break

    def default_machine_state(self):
        """
            Build CPU environment with symbolic register values
        """

        ##TODO: architecture independent, should be easy
        tracked = {}
        for reg in ArchAMD64.register_list:
            tracked[reg.name] = claripy.BVS(reg.name, reg.size*8)

        tracked['rbp']  = claripy.BVV(self.stack_base, 64)
        tracked['rsp']  = tracked['rbp'] - claripy.BVV(self.stack_size, 64)
        tracked['fs']   = claripy.BVV(self.fs_default, 64)
        tracked['gs']   = claripy.BVV(self.gs_default, 64)
        return tracked

    def default_concrete_machine_state(self):
        """
            Build CPU environment with symbolic register values
        """

        ##TODO: architecture independent, should be easy
        tracked = {}
        for reg in ArchAMD64.register_list:
            tracked[reg.name] = claripy.BVV(0, reg.size*8)

        tracked['rbp']  = claripy.BVV(self.stack_base, 64)
        tracked['rsp']  = tracked['rbp'] - claripy.BVV(self.stack_size, 64)
        tracked['fs']   = claripy.BVV(self.fs_default, 64)
        tracked['gs']   = claripy.BVV(self.gs_default, 64)
        return tracked

    #0.5s timeout
    @timeout_decorator.timeout(1.0, use_signals=True)
    def _get_cardinality(self, expr):
        return expr.cardinality

    def _get_expr_reg(self, irsb, expr):
        if not isinstance(expr, pyvex.expr.Get):
            raise TypeError("expr should be a Get pyVEX Expression")

        return irsb.arch.translate_register_name(expr.offset, expr.result_size(irsb.tyenv)//8)

    def _expr_tmp_args(self, expr):
        tmp_args = set([])

        if hasattr(expr, 'tmp'):
            tmp_args.add(expr.tmp)

        if hasattr(expr, 'args'):
            for arg in expr.args:
                tmp_args = tmp_args.union( self._expr_tmp_args(arg) )

        return tmp_args

    def _expr_name(self, irsb, expr):
        if isinstance(expr, pyvex.expr.Get):
            return self._get_expr_reg(self, irsb, expr)

        if isinstance(expr, pyvex.expr.RdTmp):
            return expr.tmp

        if isinstance(expr, pyvex.expr.Const):
            return 'c_' + str( expr.con.value )

        if isinstance(expr, pyvex.expr.Load):
            #return self._expr_name(expr.addr)
            #return 'm_(' + self._expr_name(irsb, expr.addr) + ')'
            return 'm_' + self._expr_name(irsb, expr.addr)
        
        self.logger.error("Error not implemented")
        #IPython.embed()
        raise TypeError("Error not implemented")

    def get_expr_val(self, irsb, expr):
        """
            Get a BitVector value for expression
        """
        if isinstance(expr, pyvex.expr.Const):
            size = expr.result_size(irsb.tyenv)
            value = expr.con.value
            if isinstance(value, int):
                return claripy.BVV(value, size)
            elif isinstance(value, float):
                fsort = claripy.FSORT_DOUBLE if size == 64 else claripy.FSORT_FLOAT
                return claripy.FPV(value, fsort)
            else:
                print("Unknown value type.")
                IPython.embed()


        elif isinstance(expr, pyvex.expr.RdTmp):
            if expr.tmp in self.machine_state:
                return self.machine_state[expr.tmp]
            else:
                self.logger.error("Did not track tmp var {}".format(expr.tmp))
                IPython.embed()
                raise RuntimeError("Did not track tmp var {}".format(expr.tmp))

        elif isinstance(expr, pyvex.expr.Get):
            ##get register
            reg_name = self._get_expr_reg(irsb, expr) 
            return self._get_register_value(reg_name)

        elif isinstance(expr, pyvex.expr.Load):
            return self.get_expr_val(irsb, expr.addr)

        self.logger.error("Error, unknown expression type")
        IPython.embed()
        return claripy.BVS("memory", expr.result_size(irsb.tyenv))

    def _handle_store_stmt(self, bb, stmt):
        in_vars, out_vars = set([]), set([])
        exprs = list(stmt.expressions)

        #need to taint target location of store if input is tainted 
        name = self._expr_name( bb.irsb, exprs[1] )
        in_vars.add(name)

        if isinstance(stmt.addr, pyvex.expr.RdTmp):
            if stmt.addr.tmp in self.machine_state:
                addr_target = self.machine_state[ stmt.addr.tmp ]

        elif isinstance(stmt.addr, pyvex.expr.Const):
            addr_target = claripy.BVV( stmt.addr.con.value, stmt.addr.result_size(bb.irsb.tyenv))

        addr_target  = self.get_expr_val( bb.irsb, exprs[0])
        mem_value = self.get_expr_val( bb.irsb, exprs[1])

        ##track memory locations byte wise
        if addr_target.concrete:
            try:
                solved = self.solver.eval(addr_target, 1)
                val = solved[0]
                #print("Adding tracked memory addresses")
                ##write mem_value to memory in bytes, write size of mem_value
                for i in range( mem_value.size() // 8 ):
                    self.machine_state[ 'm_' + str(hex(val + i)) ] = mem_value.get_bytes(i, 1)
                    out_vars.add( 'm_' + str(hex(val + i)) )
            except Exception as e:
                self.logger.error("Failed to get concrete bytes")
                self.logger.error(e)
                self.logger.warning("Cannot get concrete address. Not tainting memory location.")
        else:
            try:
                num_possible_values = self._get_cardinality(addr_target)
            except:
                num_possible_values = math.inf
            if num_possible_values <= 4:
                try:
                    solved = self.solver.eval(addr_target, num_possible_values)
                    ##for each solution, taint all memory locations :D
                    for val in solved:
                        for i in range( mem_value.size() // 8 ):
                            self.machine_state[ 'm_' + str(hex(val + i)) ] = mem_value.get_bytes(i, 1)
                            out_vars.add( 'm_' + str(hex(val + i)) )
                except Exception as e:
                    pass
            else:
                self.logger.debug("Unbound symbolic expression as the address for a store statement. Not tainting {} memory locations.".format(num_possible_values))

        if len(exprs) != 2:
            self.logger.error("Error, cannot handle Store with args != 2")
            IPython.embed()
            raise Exception("Error, cannot handle Store with args != 2")

        for expr in exprs:
            ## Get name of register
            if isinstance(expr, pyvex.expr.Get):
                in_vars = in_vars.union( set([ self._get_expr_reg(bb.irsb, expr) ]) )
                ## Get name of temporary variable
            elif isinstance(expr, pyvex.expr.RdTmp):
                in_vars = in_vars.union( self._expr_tmp_args(expr) )

        ##pass the taint
        ##for each dependent variable
        if len(in_vars.intersection(self.tainted)) > 0:
            #if dependent variable is tainted, taint output
            for var in out_vars:
                self.tainted.add(var)

        return in_vars, out_vars
    
    def _handle_exit_stmt(self, bb, stmt):
        in_vars, out_vars = set([]), set([])
        exprs = list(stmt.expressions)
        ##get live variables
        #jumping to stmt.dst.value

        ##find if jump is conditioned on tainted variable
        if stmt.jk == 'Ijk_Boring':
            ##conditional jump
            for expr in exprs:
                ##assume jump is conditioned on expression
                name = self._expr_name(bb.irsb, expr)
                #self.logger.debug("JUMP IS CONDITIONED ON {}".format(name))
                in_vars.add( name )
                out_vars.add( 'l_' + str( hex(stmt.dst.value) ) )

        elif stmt.jk == 'Ijk_Call':
            ##extract args and map tmp variables to function arguments
            #add function addres to flows
            flows.append( stmt.dst.value )
            out_vars.add( 'l_' + str( hex(stmt.dst.value) ) )

        elif stmt.jk == 'Ijk_Ret':
            flows.append( stmt.dst.value )
            out_vars.add( 'l_' + str( hex(stmt.dst.value) ) )

        return in_vars, out_vars

    def _enforce_register_sizes(self):
        for reg in ArchAMD64.register_list:
            if self.machine_state[reg.name].size() != (8*reg.size):
                print("Error! {} is of size {} and should be {}".format(reg.name, self.machine_state[reg.name].size(), 8*reg.size))
                IPython.embed()

    def _get_register_value(self, reg_name):
        """
            Sets the internal value of a register and updates taints
        """
        for reg in ArchAMD64.register_list:

            ##setting top level register
            if reg_name == reg.name:
                return self.machine_state[reg.name]
        
            ##setting alias for top level register
            if hasattr(reg, 'alias_names'):
                if reg_name in reg.alias_names:
                    return self.machine_state[reg.name]

            ##setting sub-register
            if hasattr(reg, 'subregisters'):
                for s_reg_name, s_reg_start, s_reg_size in reg.subregisters:
                    if s_reg_name == reg_name:
                        return claripy.Extract(
                                ((s_reg_start+s_reg_size)*8)-1,
                                (s_reg_start*8),
                                self.machine_state[reg.name])

        #raise RuntimeError("Error getting value for register: {}".format(reg_name))
        self.logger.error("Error getting value for register: {}".format(reg_name))
        #IPython.embed()
        if reg_name in self.machine_state:
                return self.machine_state[reg_name]

        return claripy.BVS("UNKNOWN REGISTER AND SIZE - guessing 64 bits", 64)

    def _set_register_value(self, reg_name, value):
        """
            Sets the internal value of a register and updates taints
        """
        for reg in ArchAMD64.register_list:

            ##setting top level register
            if reg_name == reg.name:
                self.machine_state[reg.name] = value
                return
        
            ##setting alias for top level register
            if hasattr(reg, 'alias_names'):
                if reg_name in reg.alias_names:
                    self.machine_state[reg.name] = value
                    return

            #check value is a bitvector
            value = value.to_bv()

            ##setting sub-register
            if hasattr(reg, 'subregisters'):
                for s_reg_name, s_reg_start, s_reg_size in reg.subregisters:
                    if s_reg_name == reg_name:
                        assert(s_reg_size * 8 == value.size())

                        ##update top level register
                        if s_reg_start == 0:
                            ## updated value is at the bottom of the register
                            tmp = claripy.Concat(
                                    claripy.Extract(
                                        (reg.size*8)-1,
                                        ((s_reg_start+s_reg_size)*8),
                                        self.machine_state[reg.name]
                                    ),
                                    value
                                )
                            if tmp.size() != self.machine_state[reg.name].size():
                                print("invalid size 1")
                                IPython.embed()
                                raise RuntimeError("BV sizes do not match for\
                                {} and {} (reg {})".format(tmp,
                                    self.machine_state[reg.name], 
                                    reg.name))
                            self.machine_state[reg.name] = tmp

                        elif s_reg_start + s_reg_size == reg.size:
                            ## updated value is at the top of the register
                            tmp = claripy.Concat(
                                    value,
                                    claripy.Extract(
                                        (s_reg_start*8)-1,
                                        0,
                                        self.machine_state[reg.name]
                                    )
                                )

                            if tmp.size() != self.machine_state[reg.name].size():
                                print("invalid size 2")
                                IPython.embed()
                                raise RuntimeError("BV sizes do not match for\
                                {} and {} (reg {})".format(tmp,
                                    self.machine_state[reg.name], 
                                    reg.name))

                            self.machine_state[reg.name] = tmp
                        else:
                            ## updated value is in the middle of the register
                            tmp = claripy.Concat(
                                    claripy.Extract((8*reg.size)-1, 
                                            (8*(s_reg_start + s_reg_size)), 
                                            self.machine_state[reg.name]
                                    ),
                                    value,
                                    claripy.Extract(
                                        (s_reg_start*8)-1,
                                        0,
                                        self.machine_state[reg.name]
                                    )
                                )
                           
                            if tmp.size() != self.machine_state[reg.name].size():
                                print("invalid size 3")
                                IPython.embed()
                                raise RuntimeError("BV sizes do not match for\
                                {} and {} (reg {})".format(tmp,
                                    self.machine_state[reg.name], 
                                    reg.name))

                            self.machine_state[reg.name] = tmp
                        return

        #raise RuntimeError("Error setting value for register: {}".format(reg_name))
        self.logger.error("Error setting value for register: {}".format(reg_name))
        #IPython.embed()
        self.machine_state[reg_name] = value

    def is_reg_tainted(self, reg_name):
        for reg in ArchAMD64.register_list:
            if reg.name in self.tainted:
                return True

            if hasattr(reg, 'alias_names') and reg_name in reg.alias_names:
                return True

            if hasattr(reg, 'subregisters'):
                for sr_name, sr_start, sr_size in reg.subregisters:
                    if sr_name == reg_name:
                        return True

        return False
        
    def _reg_name_to_size(self, reg_name):
        #TODO: reimplement this

        ##vex special registers
        """
        if reg_name in ['cc_op', 'cc_dep1', 'cc_dep2', 'cc_ndep', 'nraddr', 'd', 'ac', 'fpround', 'ftop', 'cmstart', 'cmlen', 'ip_at_syscall', 
                'idflag', 'emnote', 'sseround', 'fsc3210' ]:
            return 64
        """

        for reg in ArchAMD64.register_list:
            if reg.name == reg_name:
                return 8 * reg.size
            if hasattr(reg, 'alias_names') and reg_name in reg.alias_names:
                return 8 * reg.size

            if hasattr(reg, 'subregisters'):
                for sr_name, sr_start, sr_size in reg.subregisters:
                    if sr_name == reg_name:
                        return sr_size * 8

        self.logger.error("ARCHINFO DOES NOT CONTAIN SIZE INFORMATION FOR\
        REGISTER: {}".format(reg_name))

        return 64

        raise RuntimeError("Unknown register size for {}".format(reg_name))


    def _overlay_bv_on_reg(self, reg_name, arg):
        l = arg.size()
        d = self._reg_name_to_size(reg_name)

        if d == l:
            return arg

        if d <= 0:
            print("Errrr d")
            IPython.embed()

        ##convert floats to bitvectors
        if isinstance(arg, claripy.ast.fp.FP):
            try:
                arg = arg.to_bv()
            except Exception as e:
                print(e)
                print("Error converting float to BV")
                IPython.embed()
                arg = claripy.BVS("invalid_fp_to_bv_conversion", l)
        if not (isinstance(arg, claripy.ast.bv.BV)):
            raise RuntimeError("arg must be a bitvector")

        if d < l:
            return self._bv_lower_n(arg, d)

        ###register size is greater than arg, 0 extend
        return claripy.Concat( claripy.Extract(d-1, l,
            self._get_register_value(reg_name)), arg)
            
            
    def _handle_put_stmt(self, bb, stmt):
        in_vars, out_vars = set([]), set([])
        exprs = list(stmt.expressions)

        out_reg_name = bb.irsb.arch.translate_register_name(stmt.offset, stmt.data.result_size(bb.irsb.tyenv) // 8)
        self.tainted = self.tainted - set([ out_reg_name ])

        """
        if type
            I need to ensure consitency between register references e.g. dl -> rdx
            This is done calling _update_register_mappings2
        """
        ###TODO updated tracked variable 
        if len(exprs) != 1:
            self.logger.error("Unhandled number of arguments to Put")
            IPython.embed()
            raise RuntimeError("Unhandled number of arguments to Put")

        #update tracked value
        bv_in = self.get_expr_val( bb.irsb, exprs[0])

        if type(bv_in) == type(NotImplemented):
            print("put stmt NotImplemented")
            IPython.embed()

            bv_in = claripy.BVS("NotImplemented-{}".format(out_reg_name), stmt.data.result_size(bb.irsb.tyenv))

        #if bv_in.size() != stmt.data.result_size(bb.irsb.tyenv):
        bv_in_mod = self._overlay_bv_on_reg(out_reg_name, bv_in)
        #bv_in = self._PYVEX_FIX_force_size_by_reg_name(out_reg_name, bv_in)
        if type(bv_in_mod) == type(NotImplemented):
            print("Invalid value type - not implemented")
            IPython.embed()

        bv_in = bv_in_mod

        """
        if bv_in.size() != stmt.data.result_size(bb.irsb.tyenv):
            self.logger.warning("ERROR! Mismatch in register/variable size for\
                    InstPUT! This could be VEX messing up")
            print("Check bv_in size! Only write bv_in to register")
            IPython.embed()
        """
        self._set_register_value(out_reg_name, bv_in)

        ##if putting const, kill reg
        if isinstance(exprs[0], pyvex.expr.Get):
            in_reg_name = self._get_expr_reg(bb.irsb, exprs[0])

            if self.is_reg_tainted(in_reg_name):
                self.tainted.add(out_reg_name)
        elif isinstance(exprs[0], pyvex.expr.RdTmp):
            if exprs[0].tmp in self.tainted:
                self.tainted.add(out_reg_name)

        return in_vars, out_vars

    def _read_memory(self, addr, size_in_bytes):
        """
            Read memory, unknown memory address return symbolic values
            Check memory in self.machine_state, then tries self.fixed_memory,
            then cheats and uses symbolic memory values
        """
        self.logger.debug("Reading {} bytes from memory".format(size_in_bytes))
        tracked_bytes = [] 
        for i in range(size_in_bytes):
            mkey = 'm_' + str(hex(addr + i))
            if mkey in self.machine_state:
                self.logger.debug("Tracked memory read for {}".format(mkey))
                tracked_bytes.append( self.machine_state[mkey] )
            elif mkey in self.fixed_memory:
                self.logger.debug("Copying memory from fixed data for {}\
                        section".format(mkey))
                ##needs to be copied to machine_state for analysis of bytes read
                self.machine_state[mkey] = self.fixed_memory[mkey]
                tracked_bytes.append( self.machine_state[mkey] )
            else:
                self.logger.debug("Address is not tracked: {}".format(hex(addr + i)))
                self.logger.debug("Program must be loading in variables via registers or heap memory. Using symbolic values.")
                symb_byte = claripy.BVS("symb." + mkey, 8)
                tracked_bytes.append( symb_byte )

        tracked_val = claripy.Concat(*tracked_bytes)
        return tracked_val
 
    def _handle_imark_stmt(self, bb, stmt):
        """
            Update instruction pointer
        """
        in_vars, out_vars = set([]), set([])
        ##update rip before executing the current instruction
        ip = claripy.BVV(stmt.addr, 64) + claripy.BVV(stmt.len, 64)
        self._set_register_value('rip', ip)
        return in_vars, out_vars
 
    def _handle_dirty_stmt(self, bb, stmt):
        """
            Dirty statements are helpers for CISC instruction such as SHA512, AES funcs
            I can't just making the output symbolic, these helper functions change the CPU state in unknow ways e.g. cpuid puts 
            saves a value into rdi

            I would need to implement taint tracking across all helper functions
        """
        in_vars, out_vars = set([]), set([])
        if hasattr(stmt, 'tmp'):
            size_in_bytes = 8 ##cannot find solid way to get temp value size is bytes, assume 8
            self.machine_state[ stmt.tmp ] = claripy.BVS("symb_addr_val.DIRTY", size_in_bytes*8)
            out_vars.add( stmt.tmp )

        exprs = list(stmt.expressions)
        for expr in exprs:
            in_vars.add( self._expr_name( bb.irsb, expr ) )

        return in_vars, out_vars

            
    def _handle_cas_stmt(self, bb, stmt):
        """
            statement has 2 types, double and single.
            if the value read in from stmt.addr is equal to value in expression 1, set value 
            in address to value in expression 2

            I'm not computing the CAS, just passing taints

            if  (*expr[0]) == (expr[1]):
                (stmt.addr) = expr[2]

                In the double case, the swap only happens when both values are equal!
        """
        in_vars, out_vars = set([]), set([])
        exprs = list(stmt.expressions)
        if len(exprs) not in [3, 5]:
            raise RuntimeError("Error expected either single or double CAS")

        CAS_TYPE_DOUBLE = False
        if len(exprs) == 5:
            CAS_TYPE_DOUBLE = True

        ##result of CAS is stmt.oldLo
        out_vars.add( stmt.oldLo )
        if CAS_TYPE_DOUBLE:
            out_vars.add(stmt.oldHi)

        size_in_bytes = exprs[1].result_size(bb.irsb.tyenv) // 8

        for expr in exprs:
            #the value that is moved to addr is condition is true
            if not isinstance(expr, pyvex.expr.Const):
                in_vars.add( self._expr_name( bb.irsb, expr ) )

        try:
            ##read memory value
            ##stmt.addr == stmt.exprs[0]
            addr  = self.get_expr_val(bb.irsb, exprs[0])

            COMPARAND   = []
            SETTERS     = []
            if not CAS_TYPE_DOUBLE:
                COMPARAND.append( self.get_expr_val(bb.irsb, exprs[1]) )
                SETTERS.append( self.get_expr_val(bb.irsb, exprs[2]) )
            else:
                COMPARAND.append( self.get_expr_val(bb.irsb, exprs[1]) )
                COMPARAND.append( self.get_expr_val(bb.irsb, exprs[2]) )
                SETTERS.append( self.get_expr_val(bb.irsb, exprs[3]) )
                SETTERS.append( self.get_expr_val(bb.irsb, exprs[4]) )

            #if address is symbolic, we can't do much
            if addr.symbolic:
                self.logger.warning("CAS dest address is symbolic, ret val could be anything")
                a = claripy.BVS("CAS_logical_or", size_in_bytes * 8)
                tmp_solver = claripy.Solver()
                tmp_solver.add(claripy.Or(a == COMPARAND[0], a == SETTERS[0]))
                self.machine_state[ stmt.oldLo ] = a
                if CAS_TYPE_DOUBLE:
                    b = claripy.BVS("CAS_logical_or", size_in_bytes * 8)
                    tmp_solver = claripy.Solver()
                    tmp_solver.add(claripy.Or(b == COMPARAND[1], b == SETTERS[1]))
                    self.machine_state[ stmt.oldHi ] = b
                return in_vars, out_vars

            dst_addr = self.solver.eval(addr, 1)[0]
            mem_value = self._read_memory(dst_addr, size_in_bytes)

            COMPARATOR = mem_value
            if not CAS_TYPE_DOUBLE:
                cond = COMPARATOR == COMPARAND[0]
            else:
                cond = claripy.And(COMPARATOR == COMPARAND[0], COMPARATOR == COMPARAND[1])

            ##if condition is true or false
            res = self.solver.eval(cond, 2)
            if len(res) == 2:
                a = claripy.BVS("CAS_logical_or", size_in_bytes * 8)
                tmp_solver = claripy.Solver()
                tmp_solver.add(claripy.Or(a == COMPARAND[0], a == SETTERS[0]))
                self.machine_state[ stmt.oldLo ] = a
                if CAS_TYPE_DOUBLE:
                    b = claripy.BVS("CAS_logical_or", size_in_bytes * 8)
                    tmp_solver = claripy.Solver()
                    tmp_solver.add(claripy.Or(b == COMPARAND[1], b == SETTERS[1]))
                    self.machine_state[ stmt.oldHi ] = b

            else:
                if True in res:
                    #if value at addr dest is equal to value1, set memory to value2
                    self.machine_state[ stmt.oldLo ] = SETTERS[0]
                    if CAS_TYPE_DOUBLE:
                        self.machine_state[ stmt.oldHi ] = SETTERS[1]
                else:
                    self.machine_state[ stmt.oldLo ] = COMPARAND[0]
                    if CAS_TYPE_DOUBLE:
                        self.machine_state[ stmt.oldHi ] = COMPARAND[1]

        except claripy.errors.ClaripyFrontendError as e:
            ##this solver failed to resolve
            a = claripy.BVS("CAS_logical_or.SOLVER_UNSOLVED", size_in_bytes * 8)
            self.machine_state[ stmt.oldLo ] = a
            if CAS_TYPE_DOUBLE:
                b = claripy.BVS("CAS_logical_or.SOLVER_UNSOLVED", size_in_bytes * 8)
                self.machine_state[ stmt.oldHi ] = b

        return in_vars, out_vars

    def _handle_loadg_stmt(self, bb, stmt):
        in_vars, out_vars = set([]), set([])
        exprs = list(stmt.expressions)

        ##Taint variable
        out_vars = set([stmt.dst])
        out_var = stmt.dst
        in_vars  = set([])

        ##out size not reliable
        out_size = exprs[0].result_size(bb.irsb.tyenv)

        #s = claripy.Solver()
        cond_arg    = self.get_expr_val(bb.irsb, exprs[2])
        addr        = self.get_expr_val(bb.irsb, exprs[0])
        value       = self.get_expr_val(bb.irsb, exprs[1])

        if not addr.concrete:
            addr_read = claripy.BVS("loadg.symbolic.address.read", value.size())
        else:
            addr_read = self.read_memory(self.resolve_value_concrete(addr), value.size()//8)

        try:
            V = self.solver.eval(cond_arg, 2)
        except claripy.errors.ClaripyFrontendError as e:
            ##could not solve with current solver
            ##hack to make symbolic
            V = (1, 2)
        if len(V) == 2:
            loadg = addr_read | value
        elif 1 in V:
            loadg = addr_read
        else:
            loadg = value

        self.machine_state[out_var] = loadg

        for expr in exprs:
            in_vars.add( self._expr_name( bb.irsb, expr ))

        return in_vars, out_vars

    def _handle_wrtmp_stmt_geti(self, bb, stmt, exprs, out_vars, in_vars, out_var, out_size):
        #TODO proper implementation
        #instead of making symbolic

        ##GetI statement is similar to Get reg but uses an index for rotating floating point registers 
        #used in x87 and SPARC
        ##cannot implement, skip 
        self.machine_state[ stmt.tmp ] =  claripy.BVS("geti.stmt", out_size)

        for expr in exprs:
            if isinstance(expr, pyvex.expr.RdTmp):
                in_vars.add( self._expr_name( bb.irsb, expr ))

        return in_vars

    def _handle_wrtmp_stmt(self, bb, stmt):
        in_vars, out_vars = set([]), set([])
        exprs = list(stmt.expressions)

        ##Taint variable
        out_vars = set([stmt.tmp])
        out_var = stmt.tmp
        in_vars  = set([])

        out_size = exprs[0].result_size(bb.irsb.tyenv)

        try:

            #TODO: add support for triops
            #elif exprs[0].tag == 'Iex_Triop':
            #    #in_vars = self._handle_wrtmp_stmt_triop(bb, stmt, exprs, out_vars, in_vars, out_var, out_size)

            if exprs[0].tag == 'Iex_Binop':
                in_vars = self._handle_wrtmp_stmt_binop(bb, stmt, exprs, out_vars, in_vars, out_var, out_size)
            elif exprs[0].tag == 'Iex_Unop':
                in_vars = self._handle_wrtmp_stmt_unop(bb, stmt, exprs, out_vars, in_vars, out_var, out_size)
            elif exprs[0].tag == 'Iex_Load':
                in_vars = self._handle_wrtmp_stmt_load(bb, stmt, exprs, out_vars, in_vars, out_var, out_size)
            elif exprs[0].tag == 'Iex_GetI':
                in_vars = self._handle_wrtmp_stmt_geti(bb, stmt, exprs, out_vars, in_vars, out_var, out_size)
            elif exprs[0].tag == 'Iex_CCall':
                ##cannot compute value statically, need to execute it
                self.machine_state[out_var] = claripy.BVS("ccall", 64)
                for expr in exprs[1:]:
                    in_vars.add( self._expr_name( bb.irsb, expr ) )
            elif exprs[0].tag == 'Iex_ITE':
                for expr in exprs[1:]:
                    in_vars.add( self._expr_name( bb.irsb, expr ) )

                #s = claripy.Solver()
                cond_arg    = self.get_expr_val(bb.irsb, exprs[1])
                arg1        = self.get_expr_val(bb.irsb, exprs[2])
                arg2        = self.get_expr_val(bb.irsb, exprs[3])

                ## OR floating point values is NotImplemented
                if isinstance(arg1, claripy.ast.fp.FP) or isinstance(arg1, claripy.ast.fp.FP):
                    V = self.solver.eval(cond_arg, 2)
                    if len(V) == 2:
                        r = claripy.FPS('NotImplemented FP OR', arg1.sort)
                    elif 1 in V:
                        r = arg1
                    else:
                        r = arg2
                else:
                    ##bitvector
                    arg1 = arg1.get_bytes(0, out_size//8)
                    arg2 = arg2.get_bytes(0, out_size//8)

                    V = self.solver.eval(cond_arg, 2)
                    if len(V) == 2:
                        r = arg1 | arg2
                    elif 1 in V:
                        r = arg1
                    else:
                        r = arg2
                        if 0 not in V:
                            self.logger.error("Warning in ITE, {0,1} not in eval")

                self.machine_state[out_var] = r

                #a = claripy.BVS("ITE_or", out_size)
                #tmp_solver = claripy.Solver()
                #tmp_solver.add(claripy.Or(a == self.get_expr_val(bb.irsb, exprs[2]), a == self.get_expr_val(bb.irsb, exprs[3])))
                #self.machine_state[out_var] = self.get_expr_val(bb.irsb, exprs[2], self.tainted, self.machine_state) | self.get_expr_val(bb.irsb, exprs[3], self.tainted, self.machine_state)
                #self.machine_state[out_var] = a

            elif exprs[0].tag == 'Iex_Get':
                reg_name = self._get_expr_reg(bb.irsb, exprs[0]) 
                in_vars = in_vars.union( set([ reg_name ]) )
                val = self.get_expr_val(bb.irsb, exprs[0])
                self.machine_state[out_var] = val

            elif exprs[0].tag == 'Iex_RdTmp':
                in_vars = in_vars.union( self._expr_tmp_args(exprs[0]) )
                val = self.get_expr_val(bb.irsb, exprs[0])
                self.machine_state[out_var] = val

            elif exprs[0].tag == 'Iex_Const':
                val = self.get_expr_val(bb.irsb, exprs[0])
                self.machine_state[out_var] = val

            elif exprs[0].tag == 'Iex_Triop' and exprs[0].op == "Iop_MulF64":
                arg1 = self.get_expr_val(bb.irsb, exprs[1])
                arg2 = self.get_expr_val(bb.irsb, exprs[2])
                fsort = claripy.FSORT_FLOAT if '32' in exprs[0].op else claripy.FSORT_DOUBLE

                if not isinstance(arg1, claripy.ast.fp.FP):
                    arg1 = arg1.val_to_fp(fsort)
                if not isinstance(arg2, claripy.ast.fp.FP):
                    arg2 = arg2.val_to_fp(fsort)

                self.machine_state[out_var] = arg1 * arg2

            ##Quad Operation
            elif exprs[0].tag == 'Iex_Qop' and exprs[0].op == "Iop_64x4toV256":
                self.machine_state[out_var] = claripy.Concat(*list(map(lambda x, f=self.get_expr_val, irsb=bb.irsb: f(irsb, x), exprs[1:])))

            else:
                self.logger.error("Statement performed unknown operation")
                self.logger.error(exprs[0].tag)
                self.logger.error(str(stmt))
                op_name = exprs[0].op if hasattr(exprs[0], 'op') else 'unknown'
                self.machine_state[out_var] = claripy.BVS("unknown_op::"+ op_name, out_size)
                raise TypeError("Statement performed unknown operation")

        except Exception as e:
            ###ignore all operation errors, fill with symbolic values
            self.logger.error(e)
            self.machine_state[out_var] = claripy.BVS("exception_computing_wrtmp", out_size)

        if out_var not in self.machine_state:
            self.logger.error("out_var missing from machine state")
            self.machine_state[out_var] = claripy.BVS("missing_out_var_from_operation", out_size)
        if isinstance(self.machine_state[out_var], type(NotImplemented)):
            self.logger.error("out_var is not implemented")
            #IPython.embed()
            self.machine_state[out_var] = claripy.BVS("error_carrying_out_operation", out_size)

        #TODO taint track expression used in WrTmp
        for expr in exprs[1:]:
            in_vars.add( self._expr_name( bb.irsb, expr ))

        return in_vars, out_vars


    def _fit_to_size(self, arg, size):
        if arg.size() == size:
            return arg
        if arg.size() < size:
            return self._extend_value(arg, size)
        return self._shrink_value(arg, size)

    def _handle_wrtmp_stmt_load(self, bb, stmt, exprs, out_vars, in_vars, out_var, out_size):
        addr = self.get_expr_val(bb.irsb, exprs[1])

        ##assume Load has 1 arg that is a tmp variable
        ##could also be const
        if isinstance(exprs[1], pyvex.expr.RdTmp):
            in_vars.add( exprs[1].tmp ) 

        if not addr.concrete:
            #print("Cannot track symbolic load")
            #IPython.embed()
            size_in_bits = exprs[0].result_size(bb.irsb.tyenv)
            self.machine_state[out_var] = claripy.BVS('load_from_symbolic_address', size_in_bits)
            #raise RuntimeError("Cannot track symbolic load")
        else:
            #evaluate and track memory location
            size_in_bytes = exprs[0].result_size(bb.irsb.tyenv) // 8
            try:
                solved = self.solver.eval(addr, 1)
                addr = solved[0]

                mem_value = self._read_memory(addr, size_in_bytes)
                for i in range(size_in_bytes):
                    mkey = 'm_' + str(hex(addr + i))
                    in_vars.add( mkey )

            except claripy.errors.ClaripyFrontendError as e:
                ##solver error
                mem_value = clarpy.BVS('load_SOLVER_ERROR', size_in_bytes*8)

            self.machine_state[out_var] = mem_value

        return in_vars

    def _handle_wrtmp_stmt_unop(self, bb, stmt, exprs, out_vars, in_vars, out_var, out_size):

        arg1 = self.get_expr_val(bb.irsb, exprs[1])
        #arg1_in_size     = exprs[1].result_size(bb.irsb.tyenv)
        #arg1 = self._fit_to_size(arg1, arg1_in_size)

        """
            I don't know how vector operations work or the HI encoded
            ops
        """
        OP_FABS = r'Iop_AbsF(\d+)'
        OP_NEGF = r'Iop_NegF(\d+)'

        OP_FCONV = r'Iop_F(\d{2})toF(\d{2})'

        OP_I_TO_F = r'Iop_ReinterpI(\d+)[S]*asF(\d+)'
        OP_SI_TO_F = r'Iop_I(\d{2})[S]*toF(\d{2})'

        OP_F_TO_I = r'Iop_ReinterpF(\d+)asI(\d+)[S]*'
        OP_F_TO_SI = r'Iop_F(\d{2})toI(\d{2})[S]*'

        OP_CLZ      = r'Iop_Clz(\d+)'
        OP_CTZ      = r'Iop_Ctz(\d+)'
        OP_F_SQRT  = r'Iop_Sqrt32F.*'

        OP_FABS_m = re.match(OP_FABS, exprs[0].op)
        OP_NEGF_m = re.match(OP_NEGF, exprs[0].op)

        OP_FCONV_m = re.match(OP_FCONV, exprs[0].op)

        OP_F_TO_I_m = re.match(OP_F_TO_I, exprs[0].op)
        OP_F_TO_SI_m = re.match(OP_F_TO_SI, exprs[0].op)

        OP_I_TO_F_m = re.match(OP_I_TO_F, exprs[0].op)
        OP_SI_TO_F_m = re.match(OP_SI_TO_F, exprs[0].op)

        OP_CLZ_m    = re.match(OP_CLZ, exprs[0].op)
        OP_CTZ_m    = re.match(OP_CTZ, exprs[0].op)

        OP_F_SQRT_m = re.match(OP_F_SQRT, exprs[0].op)


        if OP_I_TO_F_m or OP_SI_TO_F_m:
            m = OP_I_TO_F_m if OP_I_TO_F_m else OP_SI_TO_F_m
            fsort = claripy.FSORT_DOUBLE if m.group(2) == '64' else claripy.FSORT_FLOAT
            #self.machine_state[out_var] = claripy.FPV(arg1, fsort)
            self.machine_state[out_var] = arg1.val_to_fp(fsort)
        elif OP_F_TO_I_m:
            if isinstance(arg1, claripy.ast.fp.FP):
                try:
                    self.machine_state[out_var] = claripy.fp.fpToUBV(claripy.fp.RM_TowardsZero, arg1, out_size)
                except Exception as e:
                    self.logger.error("Error converting float to int")
                    self.logger.error(e)
                    self.machine_state[out_var] = claripy.BVS("exception converting float to int", arg1.size())
            else:
                self.logger.error("Float is already a bitvector")
                self.machine_state[out_var] = arg1

        elif OP_F_TO_SI_m:
            if isinstance(arg1, claripy.ast.fp.FP):
                self.machine_state[out_var] = claripy.fp.fpToSBV(claripy.fp.RM_TowardsZero, arg1, out_size)
            else:
                self.logger.error("Float is already a bitvector")
                self.machine_state[out_var] = arg1
        elif OP_FABS_m:
            m = OP_FABS_m
            fsort = claripy.FSORT_DOUBLE if m.group(1) == '64' else claripy.FSORT_FLOAT
            #self.machine_state[out_var] = claripy.fpAbs(claripy.FPV(arg1, fsort))
            self.machine_state[out_var] = claripy.fpAbs(arg1)
        elif OP_NEGF_m:
            self.machine_state[out_var] = -arg1
        elif OP_F_SQRT_m:
            def sqrt(x):
                #1 / fast inverse square root
                threehalfs  = claripy.FPV(1.5, claripy.FSORT_FLOAT)
                x2  = x * claripy.FPV(0.5, claripy.FSORT_FLOAT)
                i   = claripy.Concat(x2.to_bv(), x.to_bv()).raw_to_fp()
                mi  = claripy.BVV(0x5f3759df, 64) - ( i.to_bv() >> 1 )
                y   = mi.get_bytes(4, 4).raw_to_fp()
                yi  = y * ( threehalfs - (x2 * y * y) )
                return claripy.FPV(1.0, claripy.FSORT_FLOAT) / yi

            ##sqrt each float inside arg1
            n_floats    = arg1.size() // 32
            out_val     = arg1.to_bv()
            sqrts       = []
            for i in range(n_floats):
                #f = out_val.get_bytes(i*4, (i+1)*4).to_fp(claripy.FSORT_FLOAT )
                f = out_val.get_bytes(i*4, 4).raw_to_fp()
                if f.concrete:
                    sqrt_f = sqrt(f)
                else:
                    sqrt_f = claripy.BVS("sqrt.smybolic.arg", 32)

                sqrts.append( sqrt_f.to_bv() )

            out_val = claripy.Concat(*sqrts)
            self.machine_state[out_var] = out_val

        elif OP_CLZ_m:
            size = int(OP_CLZ_m.group(1))
            bit = claripy.BVV(1, 1)

            try:
                for i in range(size):
                    cond = arg1[i] & bit
                    V = self.solver.eval(cond, 2)
                    if len(V) == 2:
                        continue
                    if len(V) != 1:
                        print("Error, in CLZ")
                        IPython.embed()

                    if 1 in V:
                        break
                    else:
                        continue

                self.machine_state[out_var] = claripy.BVV(i, out_size)

            except claripy.errors.ClaripyFrontendError as e:
                self.machine_state[out_var] = claripy.BVS('OP_CLZ_SOLVER_ERROR', out_size)

        elif OP_CTZ_m:
            size = int(OP_CTZ_m.group(1))
            bit = claripy.BVV(1, 1)
            try:
                for i in range(size):
                    cond = arg1[size-(i+1)] & bit
                    V = self.solver.eval(cond, 2)
                    if len(V) == 2:
                        continue
                    if len(V) != 1:
                        print("Error, in CTZ")
                        IPython.embed()

                    if 1 in V:
                        break
                    else:
                        continue

                self.machine_state[out_var] = claripy.BVV(i, out_size)

            except claripy.errors.ClaripyFrontendError as e:
                self.machine_state[out_var] = claripy.BVS('OP_CTZ_SOLVER_ERROR', out_size)

        elif OP_FCONV_m:
            m = OP_FCONV_m
            fsort = claripy.FSORT_DOUBLE if m.group(2) == '64' else claripy.FSORT_FLOAT
            #self.machine_state[out_var] = claripy.FPV(arg1, fsort)
            if not isinstance(arg1, claripy.ast.fp.FP):
                self.machine_state[out_var] = arg1.val_to_fp(fsort)
            else:
                self.machine_state[out_var] = arg1.to_fp(fsort)
        else:
            m = re.match(r'^Iop_([V]*)(\d+)([USVHI]*)to([USV]*)(\d+)$', exprs[0].op)
            n = re.match(r'^Iop_Not[V]*(\d+)$', exprs[0].op)
            if m:
                vector      = m.group(1) == 'V'
                unsigned    = m.group(3) == 'U'
                in_base     = int( m.group(2) )
                out_base    = int( m.group(5) )



                #print("Unop of non float")
                #print(exprs[0].op)
                #print(stmt)
                #IPython.embed()

                if out_base < in_base:
                    self.machine_state[out_var] = self._bv_lower_n(arg1, out_base)
                elif out_base > in_base:
                    if unsigned:
                        self.machine_state[out_var] = self._bv_unsigned_ext_to_n(arg1, out_base)
                    else:
                        self.machine_state[out_var] = self._bv_signed_ext_to_n(arg1, out_base)
                else:
                    self.machine_state[out_var] = arg1

            elif n:
                self.machine_state[out_var] = -arg1
            else:
                self.logger.error("Statement performed unknown UnOp")
                self.logger.error(exprs[0].op)
                self.logger.error(str(stmt))
                #IPython.embed()
                self.machine_state[out_var] = claripy.BVS("unknown_op::"+ exprs[0].op, out_size)
                #raise TypeError("Statement performed unknown UnOp")

        return in_vars

    def _handle_wrtmp_stmt_binop(self, bb, stmt, exprs, out_vars, in_vars, out_var, out_size):
        arg1 = self.get_expr_val(bb.irsb, exprs[1])
        arg1_in_size     = exprs[1].result_size(bb.irsb.tyenv)
        arg1 = self._fit_to_size(arg1, arg1_in_size)

        if len(exprs) not in [2, 3]:
            self.logger.error("Error, unhandled wrtmp binop")
            IPython.embed()

        if len(exprs) == 2:
            if 'Not' in exprs[0].op:
                self.machine_state[out_var] = -arg1
            else:
                self.logger.error("Statement performed unknown BinOp with 2 expressions")
                self.logger.error(str(stmt))
                #IPython.embed()
                self.machine_state[out_var] = claripy.BVS("unknown_tag::"+ exprs[0].tag, out_size)
                raise TypeError("Statement performed unknown BinOp")

        elif len(exprs) == 3:
            arg2 = self.get_expr_val(bb.irsb, exprs[2])
            arg2_in_size     = exprs[2].result_size(bb.irsb.tyenv)
            arg2 = self._fit_to_size(arg2, arg2_in_size)

            ##arguments must be the same size for operations to happend
            max_size = max([arg1.size(), arg2.size()])

            arg1 = self._fit_to_size(arg1, max_size)
            arg2 = self._fit_to_size(arg2, max_size)

            try:
                ##get value from other expressions
                if 'Iop_Sub' in exprs[0].op:
                    self.machine_state[out_var] = arg1 - arg2
                elif 'Iop_Add' in exprs[0].op:
                    self.machine_state[out_var] = arg1 + arg2
                elif 'Iop_And' in exprs[0].op:
                    self.machine_state[out_var] = arg1 & arg2
                elif 'Iop_Or' in exprs[0].op:
                    self.machine_state[out_var] = arg1 | arg2
                elif 'Iop_Xor' in exprs[0].op:
                    self.machine_state[out_var] = arg1 ^ arg2
                elif 'Iop_Div' in exprs[0].op:
                    self.machine_state[out_var] = arg1 / arg2
                elif 'Iop_Mod' in exprs[0].op:
                    self.machine_state[out_var] = arg1 % arg2
                elif 'Iop_Mul' in exprs[0].op:
                    self.machine_state[out_var] = arg1 * arg2
                elif 'Iop_Shl' in exprs[0].op:
                    if arg2.symbolic:
                        self.machine_state[out_var] = claripy.BVS("symbolic_shl", out_size)
                    else:
                        shift = self.solver.eval( arg2, 1)[0]
                        zeros = claripy.BVV(0, shift)
                        cc = claripy.Concat(arg1, zeros)
                        self.machine_state[out_var] = claripy.Extract(out_size-1, 0, cc)
                elif 'Iop_Shr' in exprs[0].op:
                    if arg2.symbolic:
                        self.machine_state[out_var] = claripy.BVS("symbolic_shr", out_size)
                    else:
                        shift = self.solver.eval( arg2, 1)[0]
                        zeros = claripy.BVV(0, shift)
                        cc = claripy.Concat(zeros, arg1)
                        self.machine_state[out_var] = claripy.Extract(cc.size()-1, shift, cc)
                elif 'Iop_Sar' in exprs[0].op:
                    self.machine_state[out_var] = arg1 >> arg2
                elif 'Iop_Sal' in exprs[0].op:
                    self.machine_state[out_var] = arg1 << arg2
                elif 'CmpGT' in exprs[0].op:
                    #a = claripy.BVV(1, out_size)
                    #IPython.embed()
                    #self.machine_state[out_var] = self.build_cond_vec(a, arg1 > arg2, 0, 1, 0)
                    self.machine_state[out_var] = self.fast_cond_eval(arg1 > arg2)
                elif 'CmpGE' in exprs[0].op:
                    #a = claripy.BVV(1, out_size)
                    #IPython.embed()
                    #self.machine_state[out_var] = self.build_cond_vec(a, arg1 >= arg2, 0, 1, 0)
                    self.machine_state[out_var] = self.fast_cond_eval(arg1 >= arg2)
                elif 'CmpLT' in exprs[0].op:
                    #a = claripy.BVV(1, out_size)
                    #IPython.embed()
                    #self.machine_state[out_var] = self.build_cond_vec(a, arg1 < arg2, 0, 1, 0)
                    self.machine_state[out_var] = self.fast_cond_eval(arg1 < arg2)
                elif 'CmpLE' in exprs[0].op:
                    #a = claripy.BVV(1, out_size)
                    #IPython.embed()
                    #self.machine_state[out_var] = self.build_cond_vec(a, arg1 <= arg2, 0, 1, 0)
                    self.machine_state[out_var] = self.fast_cond_eval(arg1 <= arg2)
                elif 'CmpEQ' in exprs[0].op:
                    #a = claripy.BVV(1, out_size)
                    #IPython.embed()
                    #self.machine_state[out_var] = self.build_cond_vec(a, arg1 == arg2, 0, 1, 0)
                    self.machine_state[out_var] = self.fast_cond_eval(arg1 == arg2)
                elif 'CmpNE' in exprs[0].op:
                    #a = claripy.BVV(1, out_size)
                    #IPython.embed()
                    #self.machine_state[out_var] = self.build_cond_vec(a, arg1 != arg2, 0, 1, 0)
                    self.machine_state[out_var] = self.fast_cond_eval(arg1 != arg2)
                elif 'CmpF' in exprs[0].op:
                    """
                        Floating point vec comparison
                        x86_64 - UCOMISS

                        32 bit ELFGAS reg result
                        OF, SF, AF are 0.
                        ZF, PF, CF are set for unordered, greater than, less than, equal
                    """
                    """
                    farg1, farg2 = arg1, arg2

                    print("comparing floats")
                    IPython.embed()

                    eflags = claripy.BVV(0x2, out_size)
                    eflags = self.build_cond_vec(eflags, farg1 == farg2, ZERO_FLAG_BIT, 1, 0)
                    eflags = self.build_cond_vec(eflags, farg1 > farg2, PARITY_FLAG_BIT, 1, 0)
                    eflags = self.build_cond_vec(eflags,
                            claripy.Or(
                                claripy.fpIsInf(farg1), claripy.fpIsInf(farg2),
                                claripy.fpIsNaN(farg1), claripy.fpIsNaN(farg2)
                                )
                            , CARRY_FLAG_BIT, 1, 0)


                    self.machine_state[out_var] = eflags
                    """
                    #a = claripy.BVV(1, out_size)
                    #self.machine_state[out_var] = self.build_cond_vec(a, arg1 == arg2, 0, 1, 0)
                    self.machine_state[out_var] = self.fast_cond_eval(arg1 == arg2)
                elif 'HLto' in exprs[0].op:
                    ##concat 2 32 bit numbers into 64 bit
                    self.machine_state[out_var] = claripy.Concat(arg1, arg2)
                elif 'Interleave' in exprs[0].op:
                    if 'HI' in exprs[0].op:
                        max_bit = out_size // 2
                        assert(max_bit % 2 == 0)
                        self.machine_state[out_var] = self._interleave(out_size, arg1[out_size-1:max_bit], arg2[out_size-1:max_bit])
                    elif 'LO' in exprs[0].op:
                        max_bit = out_size // 2
                        assert(max_bit % 2 == 0)
                        self.machine_state[out_var] = self._interleave(out_size, arg1[max_bit:], arg2[max_bit:])
                    else:
                        ##concat 2 32 bit numbers into 64 bit
                        self.machine_state[out_var] = self._interleave(out_size, arg1, arg2)
                elif 'toF' in exprs[0].op:
                    #arg1 is the IRrounding argument
                    fp = arg2.raw_to_fp()
                    fsort = claripy.FSORT_DOUBLE if out_size == 64 else claripy.FSORT_FLOAT
                    self.machine_state[out_var] = fp.to_fp(fsort)

                elif 'toI' in exprs[0].op:
                    #arg1 is the IRrounding argument
                    ## Claripy internal bug, cannot convert floatto bitvector
                    #self.machine_state[out_var] = arg2.to_bv() 
                    self.machine_state[out_var] = claripy.BVS("({})_to_bv".format(str(arg2)),  out_size)
                elif 'SetV128lo32' in exprs[0].op:
                    #set lower 32 bits of a 128 bitvector
                    if isinstance(arg2, claripy.ast.fp.FP):
                        arg2 = arg2.to_bv()
                    self.machine_state[out_var] = claripy.Concat(arg1.get_bytes(0, 12), arg2.get_bytes(0, 4))
                else:
                    self.logger.error("Statement performed unknown binary operation with 3 expressions")
                    self.logger.error(exprs[0].op)
                    self.logger.error(str(expr))
                    #IPython.embed()
                    self.machine_state[out_var] = claripy.BVS("unknown_op::"+ exprs[0].op, out_size)
                    #raise Exception("Statement performed unknown binary operation")

            except Exception as e:
                self.logger.error("exception whilst processing BinOp with 3 args")
                self.logger.error(e)
                #IPython.embed()
                #raise RuntimeError("Exception occoured processing BinOp expression")
                self.machine_state[out_var] = claripy.BVS("binop_exception"+ exprs[0].op, out_size)

        return in_vars

    def _interleave(self, out_size, a, b):
        """
            Interleave bits of a and b
        """
        l = claripy.BVV(0, 0)
        for i in range(out_size):
            if i % 2 == 1:
                l = claripy.Concat(l, a[i//2])
            else:
                l = claripy.Concat(l, b[i//2])
        return l

    def _bv_lower_n(self, arg, n):
        """ Convert Bitvector to lower 32 bits """
        return claripy.Extract(n-1, 0, arg)

    def _bv_to_l1(self, arg):
        """ Convert Bitvector to lower 1 bits """
        return self._bv_lower_n(arg, 1)

    def _extend_value(self, value, size, signed=False):
        if not isinstance(value, claripy.ast.fp.FP) and not isinstance(value, claripy.ast.bv.BV):
            self.logger.error("Error, unknown value type {} passed to\
                        sse._extend_value".format(type(value)))
            IPython.embed()

        if value.size() == size:
            return value

        if isinstance(value, claripy.ast.fp.FP):
            if size not in [32, 64]:
                self.logger.error("Cannot extend float to size {}".format(size))
                IPython.embed()
            return self._extend_float(value, size)

        ##BV
        if signed:
            return self._bv_signed_ext_to_n(value, size)
        return self._bv_signed_ext_to_n(value, size)

    def _shrink_value(self, value, size, signed=False):
        if not isinstance(value, claripy.ast.fp.FP) and not isinstance(value, claripy.ast.bv.BV):
            self.logger.error("Error, unknown value type {} passed to\
                        sse._extend_value".format(type(value)))
            IPython.embed()

        if value.size() == size:
            return value

        if isinstance(value, claripy.ast.fp.FP):
            if size not in [32, 64]:
                self.logger.error("Cannot extend float to size {}".format(size))
                IPython.embed()
            return self._extend_float(value, size)

        ##BV
        if signed:
            return self._bv_signed_ext_to_n(value, size)
        return self._bv_signed_ext_to_n(value, size)



    def _extend_float(self, fp_in, size):
        if not size == 64:
            print("Error, float not being extended to 64")
            IPython.embed()
            raise RuntimeError("Cannot extend float past 64 bits")

        return claripy.FPV(fp_in, claripy.FSORT_DOUBLE)

    def _shrink_float(self, fp_in, size):
        if not size == 32:
            self.logger.error("Cannot shrink float to anything other than 32 bits")
            raise RuntimeError("Cannot shrink float to {} bits".format(size))
        return claripy.FPV(fp_in, claripy.FSORT_FLOAT)

    def _bv_unsigned_ext_to_n(self, arg, n):
        """ Unsigend extended variable to n bits """
        if not isinstance(arg, claripy.ast.bv.BV):
            self.logger.error("Error, FP value passed to unsigned extend")
            IPython.embed()

        d = arg.size()
        if d > n:
            return self._bv_lower_n(arg, n)
            raise RuntimeError("Error extending to smaller size")

        ##TODO: Check return value is valid
        return claripy.ZeroExt(n-d, arg)

    def _bv_signed_ext_to_n(self, arg, n):
        """ Signed extended variable to n bits """
        if not isinstance(arg, claripy.ast.bv.BV):
            self.logger.error("Error, FP value passed to unsigned extend")
            IPython.embed()

        d = arg.size()
        if d == n:
            return arg

        if(d > n):
            return self._bv_lower_n(arg, n)
        try:
            v = claripy.SignExt(n-d, arg)
        except Exception as e:
            print(e)
            self.logger.error(e)
            IPython.embed()
        if isinstance(v, type(NotImplemented)):
            self.logger.error("Cannot sign extend v: {}".format(v))
            IPython.embed()
        return v

    def execute_basicblock_slice(self, bb, vars_to_track):
        """
            Warning - register value may not be correct, only tracking register
            puts where all dependants are also tracked
        """
        self.tainted = vars_to_track
        """
        beg_re = re.compile(r'reg_bb\d+_0_(.+)')
        for var in self.tainted:
            m = re.match(beg_re, str(var))
            if m:
                self.logger.info("Adding initial tainted reg values")
                self.machine_state[var] = self.machine_state[ m.group(1) ]
        """

        """
        Missing support for the following Vex Iops
        Iop_Max16Sx8
        Iop_Max64F0x2
        Iop_Min16Sx8
        Iop_Min32F0x4
        Iop_Min64F0x2
        Iop_Perm8x8
        Iop_QAdd16Sx8
        Iop_QNarrowBin16Sto8Ux16
        Iop_QNarrowBin32Sto16Sx8
        Iop_QSub16Sx8
        Iop_SetV128lo64
        Iop_Sqrt64F0x2
        """
        ##reduce tracked vars to regs in this basicblock
        reg_bb_vars_to_track = set(filter(lambda x: 'reg_bb{}_'.format(bb.vaddr) in str(x), self.tainted))

        for i, stmt in enumerate(bb.irsb.statements):
            self.logger.debug(str(stmt))
            exprs = list(stmt.expressions)
            #if len(exprs) > 0:
            #    if hasattr(exprs[0], 'op'):
            #        if 'XorV' in exprs[0].op:
            #            IPython.embed()

            self.stmt = stmt
            in_vars, out_vars = set([]), set([])

            """
                Cryptographic applications that recurse on a value many times increases symbolic value depth to unsustainable levels. Simplify with new symbolic value if too complex.
            """
            for k, v in self.machine_state.items():
                if v.depth > 18:
                    self.logger.error("Symbolic value has a depth greater than 18 symbolic values, simplifying to new symbolic value. Loosing path conditions...")
                    self.machine_state[k]   = claripy.BVS(str(k) + '_simplified', v.size())


            ##store any values that need to be tracked
            reg_re = re.compile(r'reg_bb{}_{}_(.+)'.format(bb.vaddr, i))
            for var in reg_bb_vars_to_track:
                m = re.match(reg_re, var)
                if m:
                    self.machine_state[ var ] = self.machine_state[ m.group(1) ]

            if isinstance(stmt, pyvex.stmt.WrTmp):
                if stmt.tmp in self.tainted:
                    in_vars, out_vars = self._handle_wrtmp_stmt(bb, stmt)

            if isinstance(stmt, pyvex.stmt.CAS):
                if stmt.oldLo in self.tainted:
                    in_vars, out_vars = self._handle_cas_stmt(bb, stmt)

            elif isinstance(stmt, pyvex.stmt.Dirty):
                if hasattr(stmt, 'tmp'):
                    if stmt.tmp in self.tainted:
                        in_vars, out_vars = self._handle_dirty_stmt(bb, stmt)

            elif isinstance(stmt, pyvex.stmt.LoadG):
                if stmt.dst in self.tainted:
                    in_vars, out_vars = self._handle_loadg_stmt(bb, stmt)

            elif isinstance(stmt, pyvex.stmt.Put):
                """
                    Multiple writes to registers in same bb, may execute
                    statement I'm not tracking data dependency for
                    e.g. rip = a + b

                    Need to check all deps are covered
                """
                try:
                    out_reg_name = bb.irsb.arch.translate_register_name(stmt.offset, stmt.data.result_size(bb.irsb.tyenv) // 8)
                    base_reg_name = "reg_bb{}_{}_{}".format(bb.vaddr, i, LiveVariables.base_reg_name(out_reg_name))

                    in_vars, out_vars = self._handle_put_stmt(bb, stmt)
                    if base_reg_name in self.tainted:
                        self.machine_state[base_reg_name] = self.machine_state[LiveVariables.base_reg_name(out_reg_name)]
                except Exception as e:
                    self.logger.error(e)

            

    def execute_basicblock(self, bb):
        """
            Context sensitive, taint analysis. Produce map of { arg : [ funcs ] }
            frozenset of [ irsb start vaddr, irsb end vaddr, live tainted vars ]

            #TODO: detect junk instructions and remove them
        """
        if not bb.irsb:
            self.logger.warn("Invalid IRSB basic block passed to execute - probably 0 sized.")
            return

        self.bb = bb

        #bb.irsb.pp()
        for stmt in bb.irsb.statements:
            self.stmt = stmt
            in_vars, out_vars = set([]), set([])


            #todo: cannot handle
            #   Iop_GetMSBs8x16
            # binary expression with 3 ops Iop_QSub8Ux16
            ## t24 = 64x4toV256(t3,t3,t3,t3)

            """ Missing operations
            Iop_GetMSBs8x16
            Iop_Max8Ux16
            Iop_Sqrt32F0x4
            Iop_Min8Ux16
            Iop_Perm8x8
            Iop_QSub8Ux16
            Iop_V256toV128_0
            Iop_V256toV128_1
            """


            #or isinstance(stmt, pyvex.stmt.CAS) or isinstance(stmt, pyvex.stmt.LLSC):
            if isinstance(stmt, pyvex.stmt.Store):
                in_vars, out_vars = self._handle_store_stmt(bb, stmt)

            elif isinstance(stmt, pyvex.stmt.Exit):
                in_vars, out_vars = self._handle_exit_stmt(bb, stmt)

            #kill registers, never a tmp variable since ssa
            elif isinstance(stmt, pyvex.stmt.Put):
                in_vars, out_vars = self._handle_put_stmt(bb, stmt)

            elif isinstance(stmt, pyvex.stmt.WrTmp):
                in_vars, out_vars = self._handle_wrtmp_stmt(bb, stmt)

            elif isinstance(stmt, pyvex.stmt.CAS):
                in_vars, out_vars = self._handle_cas_stmt(bb, stmt)

            #elif isinstance(stmt, pyvex.stmt.LLSC):
            #elif isinstance(stmt, pyvex.stmt.StoreG):
            elif isinstance(stmt, pyvex.stmt.LoadG):
                in_vars, out_vars = self._handle_loadg_stmt(bb, stmt)
            elif isinstance(stmt, pyvex.stmt.MBE):
                pass
            elif isinstance(stmt, pyvex.stmt.PutI):
                ##not implemented
                pass
            elif isinstance(stmt, pyvex.stmt.IMark):
                ##ignore instruction markers
                in_vars, out_vars = self._handle_imark_stmt(bb, stmt)
                pass
            elif isinstance(stmt, pyvex.stmt.NoOp):
                ##ignore no ops
                pass
            elif isinstance(stmt, pyvex.stmt.AbiHint):
                ## AbiHint provides specific information about this platforms ABI
                ## e.g. ====== AbiHint(0xt11, 128, t4) ======
                pass
            elif isinstance(stmt, pyvex.stmt.Dirty):
                ###VEX custom helper function?
                #add symbolic return
                in_vars, out_vars = self._handle_dirty_stmt(bb, stmt)
            else:
                self.logger.error("I don't know how to deal with a {}".format(type(stmt)))
                IPython.embed()
                raise TypeError("I don't know how to deal with a {}".format(type(stmt)))

            ##pass the taint
            ##for each dependent variable
            if len(in_vars.intersection(self.tainted)) > 0:
                #if dependent variable is self.tainted, taint output
                for var in out_vars:
                    self.tainted.add(var)

        #except Exception as e:
        #    self.logger.error("Error processing basic block!")
        #    print(e)
        #    #print(bb.irsb.pp())
        #    IPython.embed()

    def bv_set_bit(self, base, mask, mask_start, mask_end):
        """
            Set a bit vector into another
        """
        assert(mask.length == 1 + (mask_start - mask_end))
        base_max = base.length - 1

        if mask_end == 0 and mask_start == base_max:
            return mask
        if mask_end == 0:
            top = claripy.Extract(base_max, mask_start + 1, base)
            return claripy.Concat(top, mask)
        if mask_start == base_max:
            bot = claripy.Extract(mask_end - 1, 0, base)
            return claripy.Concat(mask, bot)

        top = claripy.Extract(base.length - 1, mask_start + 1, base)
        bot = claripy.Extract(mask_end - 1, 0, base)

        return claripy.Concat(top, claripy.Concat(mask, bot))

    def fast_cond_eval(self, cond):
        V = self.solver.eval(cond, 2)
        if V == None or len(V) == 2:
            return claripy.BVS(str(cond), 1)
        if True in V:
            return claripy.BVV(1, 1)
        return claripy.BVV(0, 1)


    def build_cond_vec(self, eflags_base, cond, BIT, concrete_true, concrete_false):
        """
            Build eflags register for condition
            bits effected is the position of bit inside eflags register
            concrete true/false is the concrete value of a true/false

            condition must evaluate to true or false
        """
        #eflags_base = claripy.BVV(0x2, 32)
        try:
            possible_results = self.solver.eval(cond, 2)
            if len(possible_results) == 2:
                return self.bv_set_bit(eflags_base, claripy.BVS(str(cond), 1), BIT, BIT)
            else:
                if True in possible_results:
                    return self.bv_set_bit(eflags_base, claripy.BVV(concrete_true, 1), BIT, BIT)
                else:
                    return self.bv_set_bit(eflags_base, claripy.BVV(concrete_false, 1), BIT, BIT)
        except Exception as e: 
            self.logger.debug("Exception solving condition: {}".format(e))
            return self.bv_set_bit(eflags_base, claripy.BVS(str(cond), 1), BIT, BIT)

    def merge_execution_states(self):
        """
            Merges information on tainted variables and flows from all
            execution states.
        """
        t_tainted = functools.reduce( lambda x, y: x | y,
            list(map(lambda x: x.tainted, self.execution_states.values())),
            set([])
        )

        t_machine_state = {}
        for ms in map(lambda x: x.machine_state,
                self.execution_states.values()):
            t_machine_state.update(ms)

        return t_machine_state, t_tainted

    def taint_and_track_symb(self, s):
        """
            Need knowledge of all functions in binary to calculate flows, live 
            variables to functions
            :param s: Symbol
        """
        self.logger.info("Exploring symbol {} with symbolic arguments {}".format(s.name, s.vex['arguments']))

        sse, taint_info = {}, {}
        #try:
        flows = self.execute_function(s, orig_tainted=s.vex['arguments'])
        #except:
        #    self.logger.error("Failed to execute function `{}` before timeout".format(s.real_name))
        #    flows = set([])

        ##merge machine_states
        t_machine_state, t_tainted = self.merge_execution_states()
 
        taint_info['ntainted']           = len(t_tainted)

        stack_vars, heap_vars, stack_args = self._parse_mem_locs(t_machine_state.keys())
        print("Symbol:", s.name)
        #print("\tRegister classes used: {}".format(BasicBlock._registers_to_vec_classes(set(tracked.keys()))))
        print("\tStack vars read: {}".format(set(map(lambda x: hex(x), stack_vars))))
        print("\tHeap mem locations read: {}".format(set(map(lambda x: hex(x), heap_vars))))
        print("\tStack args read: {}".format(set(map(lambda x: hex(x), stack_args))))

        #Cannot store set in json
        const = 2**63  #max mongodb storage size
        sse['heap_vars']    = list(map(lambda x: x % const, heap_vars))
        sse['stack_vars']   = list(map(lambda x: x % const, stack_vars))
        sse['stack_args']   = list(map(lambda x: x % const, stack_args))
        sse['taints']       = []

        #print("\t\tself.machine_state Register classes used: {}".format(BasicBlock._registers_to_vec_classes(self.machine_state)))
        #print("\t\tFinal machine_state: {}".format(self.machine_state))
        print("\t\tFinal flows: {}".format(flows))
        t_stack_vars, t_heap_vars, t_stack_args, t_code_locs = self._parse_tainted_locs(t_tainted)
        print("\t\tTainted Stack vars: {}".format(set(map(lambda x: hex(x), t_stack_vars))))
        print("\t\tTainted Heap vars: {}".format(set(map(lambda x: hex(x), t_heap_vars))))
        print("\t\tTainted Stack args: {}".format(set(map(lambda x: hex(x), t_stack_args))))
        print("\t\tTainted Code locations (conditional jumps on tainted data): {}".format(t_code_locs))

        #taint_info['arg']              = arg
        taint_info['register_classes']  = BasicBlock._registers_to_vec_classes(t_tainted)
        taint_info['ntainted']          = len(set(filter(lambda x: isinstance(x, str), t_tainted)))
        taint_info['tainted']           = list(set(filter(lambda x: isinstance(x, str), t_tainted)))
        taint_info['nflows']            = len(flows)
        taint_info['flows']             = list(map(lambda x: list(x), flows))
        taint_info['t_stack_args']      = list(map(lambda x: x % const, t_stack_args))
        taint_info['t_stack_vars']      = list(map(lambda x: x % const, t_stack_vars))
        taint_info['t_heap_vars']       = list(map(lambda x: x % const, t_heap_vars))
        #TODO: implement number of tainted registers
        #TODO: implement tainted return value or not
        taint_info['t_code_locs']       = list(t_code_locs)
        sse['taints'].append(taint_info)

        #return flows, tracked, stack_vars, heap_vars, stack_args, t_stack_vars, t_heap_vars, t_stack_args, t_code_locs
        return sse

        ###below uses single machine state
        """
        taint_info['ntainted']           = len(self.tainted)

        print("Need to merge execution states")
        IPython.embed()

        stack_vars, heap_vars, stack_args = self._parse_mem_locs(self.machine_state.keys())
        print("Symbol:", s.name)
        #print("\tRegister classes used: {}".format(BasicBlock._registers_to_vec_classes(set(tracked.keys()))))
        print("\tStack vars: {}".format(set(map(lambda x: hex(x), stack_vars))))
        print("\tHeap vars: {}".format(set(map(lambda x: hex(x), heap_vars))))
        print("\tStack args: {}".format(set(map(lambda x: hex(x), stack_args))))

        #Cannot store set in json
        const = 2**63  #max mongodb storage size
        sse['heap_vars']    = list(map(lambda x: x % const, heap_vars))
        sse['stack_vars']   = list(map(lambda x: x % const, stack_vars))
        sse['stack_args']   = list(map(lambda x: x % const, stack_args))
        sse['taints']       = []

        #print("\t\tself.machine_state Register classes used: {}".format(BasicBlock._registers_to_vec_classes(self.machine_state)))
        #print("\t\tFinal machine_state: {}".format(self.machine_state))
        print("\t\tFinal flows: {}".format(flows))
        t_stack_vars, t_heap_vars, t_stack_args, t_code_locs = self._parse_tainted_locs(self.tainted)
        print("\t\tself.machine_state Stack vars: {}".format(set(map(lambda x: hex(x), t_stack_vars))))
        print("\t\tself.machine_state Heap vars: {}".format(set(map(lambda x: hex(x), t_heap_vars))))
        print("\t\tself.machine_state Stack args: {}".format(set(map(lambda x: hex(x), t_stack_args))))
        print("\t\tself.machine_state Code locations (conditional jumps): {}".format(t_code_locs))

        #taint_info['arg']              = arg
        taint_info['register_classes']  = BasicBlock._registers_to_vec_classes(self.tainted)
        taint_info['ntainted']          = len(set(filter(lambda x: isinstance(x, str), self.tainted)))
        taint_info['tainted']           = list(set(filter(lambda x: isinstance(x, str), self.tainted)))
        taint_info['nflows']            = len(flows)
        taint_info['flows']             = list(map(lambda x: list(x), flows))
        taint_info['t_stack_args']      = list(map(lambda x: x % const, t_stack_args))
        taint_info['t_stack_vars']      = list(map(lambda x: x % const, t_stack_vars))
        taint_info['t_heap_vars']       = list(map(lambda x: x % const, t_heap_vars))
        taint_info['t_code_locs']       = list(t_code_locs)
        sse['taints'].append(taint_info)

        #return flows, tracked, stack_vars, heap_vars, stack_args, t_stack_vars, t_heap_vars, t_stack_args, t_code_locs
        return sse
        """

    def _parse_mem_locs(self, locs):

        mem_locs = set(filter(lambda x: str(x)[:2] == 'm_', locs))
        vaddr_locs = set(map(lambda x: int(x[2:], 16), mem_locs))

        stack_vars = set(filter(lambda x,stack_start=self.stack_start,stack_end=self.stack_end: x < stack_start and x > stack_end, vaddr_locs))
        stack_args = set(filter(lambda x,stack_start=self.stack_start: x >= stack_start, vaddr_locs))
        #heap_vars = set(filter(lambda x,heap_start=heap_start: x >= heap_start, vaddr_locs))
        heap_vars = vaddr_locs.difference( stack_vars.union(stack_args) )

        return stack_vars, heap_vars, stack_args

    def _parse_tainted_locs(self, tainted):
        """
            Return the tainted stack_variables, heap_variables, stack_args, 
            and code_locations from a set of tainted 
        """
        stack_vars, heap_vars, stack_args = self._parse_mem_locs(tainted)
        code_locs = set(filter(lambda x: str(x)[:2] == 'l_', tainted))
        return stack_vars, heap_vars, stack_args, code_locs


