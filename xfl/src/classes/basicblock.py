
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

#!/usr/bin/pyhton3
import os, sys, copy
import pyvex, archinfo
import json, re
import binascii
import itertools
import pprint, socket
import logging
import hashlib
import subprocess
import numpy as np
import IPython
import collections
import timeout_decorator, math
from functools import reduce
from capstone import *
from capstone.x86_const import *
from capstone.arm_const import *
from capstone.ppc_const import *
import claripy
from archinfo.arch_amd64 import ArchAMD64
from collections import Counter

import context
from classes.config import Config
import classes.utils
import scripts.vex_classification as vexc

class BasicBlock:
    """
        If size is 0 it means we could not decompile. Alignment bytes or junk.
    """

    #Terminal functions
    NON_RETURNING_FUNCTIONS = { 'exit', 'exit_group', 'assert_fail', 'stack_check_fail', 'errx', 'err' }

    def __init__(self, config, size=-1, vaddr=-1, data=b'', vex={}, asm=[],
            opcodes=[], hash=b'', opcode_hash=b'', arch="", exits=[]):
        assert(isinstance(size, int))
        assert(isinstance(vaddr, int))
        assert(isinstance(opcodes, list))
        assert(isinstance(asm, list))
        assert(not vex or isinstance(vex, dict))
        assert(isinstance(data, bytes) or isinstance(data, str))
        assert(isinstance(hash, bytes) or isinstance(hash, str))
        assert(isinstance(opcode_hash, bytes) or isinstance(opcode_hash, str))

        classes.utils._desyl_init_class_(self, config)

        self.vaddr = vaddr
        self.size = size
        self.data = data
        self.arch = arch
        self.vex = vex
        self.exits = list(exits)
        self.asm = list(asm)
        self.opcodes = list(opcodes)
        self.hash = hash
        self.opcode_hash = opcode_hash
        self.irsb = None
        self.data_refs = set()

        for attr in [ "data", "hash", "opcode_hash" ]:
            if isinstance(self.__getattribute__(attr), str):
                if len( self.__getattribute__(attr) ) > 0:
                    self.__setattr__(attr, binascii.unhexlify( self.__getattribute__(attr) ) )

        """
        if vex:
            #vex['constant_jump_targets'] = { int(k) : value for k,value in vex['constant_jump_targets'].items() }
            #vex['constant_jump_targets'] = { k : value for k,value in vex['constant_jump_targets'].items() }
            vex['constants'] = [ list(C) for C in vex['constants'] ]
        """

        #print(self.data)
        assert(isinstance(self.data, bytes) )
        assert(isinstance(self.hash, bytes) )
        assert(isinstance(self.opcode_hash, bytes) )

        #a basic block cannot be initialised without its data
        assert(self.size == len(self.data) )
        """
        if self.size >= 5000:
            raise Exception("Error, basicblock has a size of {}. VEX cannot handle more than 5000 bytes".format(self.size))
        assert(self.size < 5000 and "VEX (and hence pyvex) cannot handle more than 5000 bytes")
        """

    def __getstate__(self):
        classes.utils._desyl_deinit_class_(self)
        return self.__dict__

    def __setstate__(self, state):
        self.__dict__ = state
        classes.utils._desyl_init_class_(self, Config())

    def analyse(self, binary):
        if self.size == 0:
            self.logger.warning("Not analysing basic block of size 0")
            return

        #gen hashes updates asm, opcdes and both hash types
        self._gen_asm()
        self._gen_opcodes()
        self.gen_hashes()
        self._gen_vex()

        if self.size != self.irsb.size:
            ##vex splits basic block for `repne scasb`  inst
            ##analyse and compound vex info until end
            t_size = self.irsb.size
            self.logger.error("VEX messed up. VEX BasicBlock is not the same size as our basicblock")
            self.logger.debug("VEX BasicBlock has size: {} and was created from data: {}".format(t_size, self.data))
            while(t_size < self.size):
                ##raise custom exception
                ##need to modify basicblock list
                raise VEXLiftingError(self.irsb.size, self.size, self.data)


                bb_hidden = BasicBlock.from_data( self.data[t_size:], 
                            self.vaddr + t_size, self.arch)

                bb_hidden._gen_vex()
                ##merge VEX analysis
                for key in ['ntemp_vars', 'operations', 'ninstructions' ]:
                    self.vex[key] += bb_hidden.vex[key]

                for key in ['constants', 'callees']:
                    self.vex[key] = self.vex[key].union(bb_hidden.vex[key])

                ##merge dictionary counts
                self.vex['temp_vars'] = dict(Counter(self.vex['temp_vars']) + Counter(self.vex['temp_vars']))

                ##take last jumpkind as jumpkind
                self.vex['jumpkind'] = bb_hidden.vex['jumpkind']

                if bb_hidden.irsb.size == 0:
                    print("Error, bb has size 0, cannot advance")
                    IPython.embed()

                t_size += bb_hidden.irsb.size

        self._vex_get_exits(binary)
        self._vex_get_data_refs()

    def _vex_get_data_refs(self):
        self.data_refs = set()
        for stmt in self.irsb.statements:
            for expr in stmt.expressions:
                if isinstance(expr, pyvex.expr.Load):
                    if isinstance(expr.addr, pyvex.expr.Const):
                        self.data_refs.add( expr.addr.con.value )

    def clone(self):
        return copy.deepcopy(self)

    """
        r2 is too slow. Use rahash2 for hashing raw bytes. However need to use objdump and regex + sha256sum to product hash of disasembled op codes only
    """
    def gen_hashes(self):
        assert(len(self.data) > 0)
        #refresh asm and opcodees, hash and opcode_hash
        self._gen_hash()
        self._gen_opcode_hash()

    def _gen_asm(self):
        self.asm.clear()

        ARCH, MODE = "", ""
        if self.arch == "x86_64":
            ARCH = CS_ARCH_X86
            MODE = CS_MODE_64
        elif self.arch == "x86" or self.arch == "x86_32":
            ARCH = CS_ARCH_X86
            MODE = CS_MODE_32
        elif self.arch == "ARMv7":
            ARCH = CS_ARCH_ARM
            MODE = CS_MODE_THUMB
        elif self.arch == "PPC64":
            ARCH = CS_ARCH_PPC
            MODE = CS_MODE_64
        else:
            logger.error("UNKNOWN ARCH: {}".format(self.arch))
            assert(False)

        md = Cs(ARCH, MODE)
        for i in md.disasm( self.data, self.vaddr):
            asm_inst = str(i.mnemonic)
            if i.op_str:
                asm_inst += " " + str(i.op_str)
            self.asm.append( asm_inst )

    def _gen_hash(self):
            hash_obj = hashlib.sha256()
            assert(len(self.data) > 0)
            assert(isinstance(self.data, bytes))
            hash_obj.update( self.data )
            self.hash = binascii.unhexlify( hash_obj.hexdigest() )

    def _gen_opcodes(self):
            self.opcodes.clear()

            ARCH, MODE = "", ""
            if self.arch == "x86_64":
                ARCH = CS_ARCH_X86
                MODE = CS_MODE_64
            elif self.arch == "x86" or self.arch == "x86_32":
                ARCH = CS_ARCH_X86
                MODE = CS_MODE_32
            elif self.arch == "ARMv7":
                ARCH = CS_ARCH_ARM
                MODE = CS_MODE_THUMB
            elif self.arch == "PPC64":
                ARCH = CS_ARCH_PPC
                MODE = CS_MODE_64
            else:
                logger.error("UNKNOWN ARCH: {}".format(self.arch))
                assert(False)

            md = Cs(ARCH, MODE)
            for i in md.disasm( self.data, self.vaddr):
                asm_inst = str(i.mnemonic)
                self.opcodes.append( asm_inst )

    def _gen_opcode_hash(self):
            hash_obj = hashlib.sha256()
            #assert(len(self.opcodes) > 0)
            assert(isinstance(self.opcodes, list))
            hash_obj.update( "\n".join(self.opcodes).encode('utf-8') )
            self.opcode_hash = binascii.unhexlify( hash_obj.hexdigest() )

    @staticmethod
    def __vex_sum_dict_elements(x, y):
        if y in x:
            x[y] += 1
        else:
            x[y] = 1
        return x

    #def _vex_find_data_symbols( r2_hndlr ):

    @staticmethod
    def _vex_gen_constants( consts, r2_hndlr ):
            #remove jumps to +- 128 from pc
            near_and_long_jumps = set(filter(lambda x: x > self.vaddr + 128 or x < self.vaddr - 128, consts))

            remove_small_consts = set(filter(lambda x: x > 256, near_and_long_jumps))

    # I cannot represent a set in JSON but want a uniuqe set of constants and types.
    # I cannot represent this as a set ( type, value ) because ordering is lost when printing to string (used in __eq__)
    # Option a) use a dict { type: a, value: b }, or just use a single list [a,b]
    # Cannot use dict{ a : b } as there are multiple a's
    # Cannot use dict{ b : a } as b is an int
    # [ [a,b], [a,b], [a,b], .... ]
    @staticmethod
    def _vex_uniq_constants( const_2d_list ):
        uniq_consts = set( map( lambda x: str(x[0]) + "\t" + str(x[1]) , const_2d_list) )
        return list( map( lambda x: [ x.split("\t")[0] , x.split("\t")[1] ], uniq_consts ) )

    def _gen_vex_py2(self):
        #s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #s.connect( ("localhost", 3001) )

        address = "/tmp/python2_vex.unix"
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect( address )


        query = { 'data' : str(binascii.hexlify(self.data)), 'vaddr': self.vaddr, 'arch': self.arch }
        s.send( json.dumps( query ).encode('utf-8') )

        res = s.recv(2 ** 16)
        #print("rcieved res: {}".format( res ))
        res_str = res.decode('utf-8')

        vex = json.loads( res_str )
        vex['operations'] = np.array( vex['operations'], dtype=np.uint64 )
        vex['expressions'] = np.array( vex['expressions'], dtype=np.uint64 )
        vex['statements'] = np.array( vex['statements'], dtype=np.uint64 )
        self.vex = vex
        #print(self.vex)

    def _gen_vex(self):
        """
            for getting constants we need to ignore all 
                - constants part of jumpkinds and targets
                - cc_op and cc_dep1, cc_dep2 pseudo registers
        """
        if len(self.data) == 0:
            raise Exception("[!] Error generating pyvex features, symbol has no data!")
        #assert(len(self.data) < 5000 and "Error, Cannot VEX basic blocks above 5000 bytes")
        assert(self.vaddr >= 0)

        self.vex = {}
        vex = {}
        try:
            if self.arch == "x86_64":
                irsb = pyvex.IRSB(self.data, self.vaddr, archinfo.ArchAMD64(), opt_level=2)
            if self.arch == "x86_32":
                irsb = pyvex.IRSB(self.data, self.vaddr, archinfo.ArchX86(), opt_level=2)
            elif self.arch == "ARMv7":
                irsb = pyvex.IRSB(self.data, self.vaddr, archinfo.ArchARM(), opt_level=2)
            elif self.arch == "PPC32":
                irsb = pyvex.IRSB(self.data, self.vaddr, archinfo.ArchPPC32(), opt_level=2)
            elif self.arch == "PPC64":
                irsb = pyvex.IRSB(self.data, self.vaddr, archinfo.ArchPPC64(), opt_level=2)

        except Exception as e:
            self.logger.error(e)
            self.logger.error("Exception occoured transforming {} @ {} into VEX".format( self.data, self.vaddr ), file=sys.stderr)
            return

        vex['ntemp_vars'] = copy.deepcopy(irsb.tyenv.types_used)
        vex['temp_vars'] = reduce( BasicBlock.__vex_sum_dict_elements, irsb.tyenv.types, {} )

        ### mongodb need strings as keys and can only handle 8 byte ints, get 18446744073709550091
        #vex['constants'] = BasicBlock._vex_uniq_constants( consts )
        ##add basic block callees #i.e. this basic block calls

        vex['callees'] = set(irsb.constant_jump_targets )

        all_consts  = set(map( lambda x: x.value, irsb.constants))
        jump_consts = vex['callees']

        """
        MongoDB limitation of 8 byte ints, cannot store 2^64 as range is 0-2^64-1
        filter consts above this range
        """
        #only store value on constants, all constants include jump args
        vex['constants'] = set(filter(lambda x: x < -1 + 2**63, all_consts - jump_consts ))
        vex['operations'] = list(irsb.operations)

        vex['jumpkind'] = irsb.jumpkind
        vex['ninstructions'] = irsb.instructions #number of vex instructions! 200 bytes -> 3 vex instr

        self.vex = vex
        self.irsb = irsb
        return

    def __vex_fast_get_const_value(self, tmp):
        """
            This is a hack to check if a tmp value has a const value.
            This resolve simple call locations such as `jmp [rip+0x223]`
        """
        for stmt in self.irsb.statements:
            if isinstance(stmt, pyvex.stmt.WrTmp):
                if stmt.tmp == tmp:
                    exprs = list(stmt.expressions)
                    if isinstance(exprs[0], pyvex.expr.Load) and isinstance(exprs[1], pyvex.expr.Const):
                        return exprs[1].con.value
                    return False
        return False

    def _vex_get_exits(self, binary):
        """
            Get address and jumpkinds out from block
            Exits are a tuple of (address, jumpkind)
            I have invented a VEX jumpkind or Ijk_AssumedRet
            Jumpkind assumes that calls return
        """
        if not isinstance(self.irsb, pyvex.block.IRSB):
            raise RuntimeError("Error getting exits from VEX. No VEX object was stored! Generate VEX first?")

        normal_exit     = "non_const_exit"
        normal_exit_jk  = self.irsb.jumpkind
        
        if isinstance(self.irsb.next, pyvex.expr.Const):
            normal_exit = self.irsb.next.con.value

        elif isinstance(self.irsb.next, pyvex.expr.RdTmp):
            val = self.__vex_fast_get_const_value( self.irsb.next.tmp )
            if val:
                normal_exit = val

        self.exits.append((normal_exit, normal_exit_jk))

        for stmt in self.irsb.statements:
            """
                Some BBs has Exit statements inside BB. lock xchngcmp loops on
                single instruction
            """
            if isinstance(stmt, pyvex.stmt.Exit):
                other_exit_jk = stmt.jumpkind
                assert(other_exit_jk != "Ijk_Call")
                other_exit = "non_const_exit"
                if isinstance(stmt.dst, pyvex.const.IRConst):
                    other_exit = stmt.dst.value

                self.exits.append((other_exit, other_exit_jk))

        ##add returns to function calls
        if normal_exit_jk == "Ijk_Call":
            if isinstance(normal_exit, int):
                ##assuming return from function call
                for interval in binary.vaddr_to_name_tree.at(normal_exit):
                    if interval.data in BasicBlock.NON_RETURNING_FUNCTIONS:
                        ##don't add AssumedRet for these function calls
                        return

            exit = self.irsb.addr + self.irsb.size
            exit_jk = "Ijk_AssumedRet"
            self.exits.append((exit, exit_jk))

    #0.5s timeout
    @timeout_decorator.timeout(0.5)
    def _get_cardinality(self, expr):
        return expr.cardinality


    def _get_expr_reg(self, offset, expr):
        if not isinstance(expr, pyvex.expr.Get):
            raise TypeError("expr should be a Get pyVEX Expression")

        reg_name = self.irsb.arch.translate_register_name(offset, expr.result_size(self.irsb.tyenv) // 8)
        return reg_name

    def _expr_tmp_args(self, expr):
        tmp_args = set([])

        if hasattr(expr, 'tmp'):
            tmp_args.add(expr.tmp)

        if hasattr(expr, 'args'):
            for arg in expr.args:
                tmp_args = tmp_args.union( self._expr_tmp_args(arg) )

        return tmp_args

    def _expr_name(self, expr):
        if isinstance(expr, pyvex.expr.Get):
            return self._get_expr_reg(self, expr.offset, expr)

        if isinstance(expr, pyvex.expr.RdTmp):
            return expr.tmp

        if isinstance(expr, pyvex.expr.Const):
            return 'c_' + str( expr.con.value )

        if isinstance(expr, pyvex.expr.Load):
            #return self._expr_name(expr.addr)
            return 'm_(' + self._expr_name(expr.addr) + ')'
        
        self.logger.error("Error not implemented")
        #IPython.embed()
        raise TypeError("Error not implemented")

    def get_expr_val(self, expr, tainted, tracked):
        """
            Get a BitVector value for expression
        """
        if isinstance(expr, pyvex.expr.Const):
            size = expr.result_size(self.irsb.tyenv)
            ##check if int types, screw implementing floating point types, return symbolic values
            if 'Ity_I' in expr.con.type:
                value = expr.con.value
                return claripy.BVV( expr.con.value, expr.result_size(self.irsb.tyenv))
            ##i don't know how to represent the bitector value of this...
            self.logger.warning("Create symbolic value for constant of type: {}, value:{}".format(expr.con.type, expr.con.value))
            return claripy.BVS( '{}_val'.format(expr.con.type), size)

        elif isinstance(expr, pyvex.expr.RdTmp):
            if expr.tmp in tracked:
                return tracked[expr.tmp]
            else:
                self.logger.error("Did not track tmp var {}".format(expr.tmp))
                #IPython.embed()
                raise RuntimeError("Did not track tmp var {}".format(expr.tmp))

        elif isinstance(expr, pyvex.expr.Get):
            ##get register
            reg_name = self._get_expr_reg(expr.offset, expr) 
            if reg_name in tracked:
                return tracked[ reg_name ]
            self.logger.error("Did not track Register {}".format( reg_name ))
            #IPython.embed()
            #raise RuntimeError("Did not track Register {}".format( reg_name ))
            size_in_bits = expr.result_size(self.irsb.tyenv)
            tracked[ reg_name ] = claripy.BVS('ERROR_UNTRACKED_REG', size_in_bits)
            return tracked[ reg_name ]

        elif isinstance(expr, pyvex.expr.Load):
            return self.get_expr_val(expr.addr, tainted, tracked)

        self.logger.error("Error, unknown expression type")
        #IPython.embed()
        return claripy.BVS("memory", expr.result_size(self.irsb.tyenv))

    def _taint_argument_handle_store_stmt(self, stmt, solver, tainted, tracked):
        in_vars, out_vars = set([]), set([])
        exprs = list(stmt.expressions)

        #need to taint target location of store if input is tainted 
        name = self._expr_name( exprs[1] )
        in_vars.add(name)

        if isinstance(stmt.addr, pyvex.expr.RdTmp):
            if stmt.addr.tmp in tracked:
                addr_target = tracked[ stmt.addr.tmp ]

        elif isinstance(stmt.addr, pyvex.expr.Const):
            addr_target = claripy.BVV( stmt.addr.con.value, stmt.addr.result_size(self.irsb.tyenv))

        addr_target  = self.get_expr_val( exprs[0], tainted, tracked)
        mem_value = self.get_expr_val( exprs[1], tainted, tracked)

        ##track memory locations byte wise
        if addr_target.concrete:
            try:
                solved = solver.eval(addr_target, 1)
                val = solved[0]
                #print("Adding tracked memory addresses")
                ##write mem_value to memory in bytes, write size of mem_value
                for i in range( mem_value.size() // 8 ):
                    tracked[ 'm_' + str(hex(val + i)) ] = mem_value.get_bytes(i, 1)
                    out_vars.add( 'm_' + str(hex(val + i)) )
            except Exception as e:
                self.logger.error("Failed to get concrete bytes")
                self.logger.error(e)
                self.logger.warning("Cannot get concrete address. Not tainting memory location.")
        else:
            #self.logger.warning("Cannot resolve symbolic address! Cannot track memory for symbolic address")
            #IPython.embed()

            try:
                num_possible_values = self._get_cardinality(addr_target)
            except:
                num_possible_values = math.inf
            if num_possible_values < 64:
                solved = solver.eval(addr_target, num_possible_values)
                ##for each solution, taint all memory locations :D
                for val in solved:
                    for i in range( mem_value.size() // 8 ):
                        tracked[ 'm_' + str(hex(val + i)) ] = mem_value.get_bytes(i, 1)
                        out_vars.add( 'm_' + str(hex(val + i)) )
            else:
                self.logger.warn("Unbound symbolic expression. Not tainting {} memory locations.".format(num_possible_values))

        if len(exprs) != 2:
            self.logger.error("Error, cannot handle Store with args != 2")
            #IPython.embed()
            raise Exception("Error, cannot handle Store with args != 2")

        for expr in exprs:
            ## Get name of register
            if isinstance(expr, pyvex.expr.Get):
                in_vars = in_vars.union( set([ self._get_expr_reg(expr.offset, expr) ]) )
                ## Get name of temporary variable
            elif isinstance(expr, pyvex.expr.RdTmp):
                in_vars = in_vars.union( self._expr_tmp_args(expr) )

        ##pass the taint
        ##for each dependent variable
        if len(in_vars.intersection(tainted)) > 0:
            #if dependent variable is tainted, taint output
            for var in out_vars:
                tainted.add(var)

        return in_vars, out_vars, tainted, tracked
    
    def _taint_argument_handle_exit_stmt(self, stmt, solver, tainted, tracked):
        in_vars, out_vars = set([]), set([])
        exprs = list(stmt.expressions)
        ##get live variables
        #jumping to stmt.dst.value

        ##find if jump is conditioned on tainted variable
        if stmt.jk == 'Ijk_Boring':
            if len(exprs) == 1:
                ##assume jump is conditioned on expression
                name = self._expr_name(exprs[0])
                #print("JUMP IS CONDITIONED ON {}".format(name))
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

        return in_vars, out_vars, tainted, tracked

    @staticmethod
    def _registers_to_vec_classes(regs):
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

    def _register_mappings(self):
        ##map registers to 32 bit values
        mapping =  {
            'sil'   : ('rsi', 0, 7),
            'sih'   : ('rsi', 8, 15),
            'si'    : ('rsi', 0, 15),
            'esi'   : ('rsi', 0, 31),

            'dil'   : ('rdi', 0, 7),
            'dih'   : ('rdi', 8, 15),
            'di'    : ('rdi', 0, 15),
            'edi'   : ('rdi', 0, 31),

            'spl'    : ('rsp', 0, 7),
            'sph'    : ('rsp', 8, 15),
            'sp'    : ('rsp', 0, 15),
            'esp'   : ('rsp', 0, 31),

            ##ipl doesn't exist (i think)
            'ipl'    : ('rip', 0, 7),
            'iph'    : ('rip', 8, 15),
            'ip'    : ('rip', 0, 15),
            'eip'   : ('rip', 0, 31),

            'bpl'    : ('rbp', 0, 7),
            'bph'    : ('rbp', 8, 15),
            'bp'    : ('rbp', 0, 15),
            'ebp'   : ('rbp', 0, 31)
        }
        for c in ['a', 'b', 'c', 'd']:
            mapping[ 'e' + c + 'x' ] = ('r' + c + 'x', 0, 31)
            mapping[ c + 'x' ] = ('r' + c + 'x', 0, 15)
            mapping[ c + 'l' ] = ('r' + c + 'x', 0, 7)
            mapping[ c + 'h' ] = ('r' + c + 'x', 8, 15)
        for i in range(8, 16):
            mapping[ 'r' + str(i) + 'd' ] = ('r' + str(i), 0, 31)
            mapping[ 'r' + str(i) + 'w' ] = ('r' + str(i), 0, 15)
            mapping[ 'r' + str(i) + 'b' ] = ('r' + str(i), 0, 7)

        for i in range(32):
            mapping[ 'ymm' + str(i) ] = ( 'zmm' + str(i), 0, 255 )
            mapping[ 'xmm' + str(i) ] = ( 'zmm' + str(i), 0, 127 )
        return mapping


    def _update_top_register(self, reg, subreg, msb, lsb):
        if lsb > 0:
            begining = claripy.Extract(lsb-1, 0, reg)
            end = claripy.Extract(reg.size()-1, msb+1, reg)
            return claripy.Concat( end, subreg, begining)
        else:
            end = claripy.Extract(reg.size()-1, msb+1, reg)
            return claripy.Concat( end, subreg)

    def _extract_subregister(self, reg, archinfo_reg):
        ##extract bits for subregister from BVS reg and archinfo reg struct
        name, start, size = archinfo_reg
        lsb = start
        msb = start + (size*8) - 1
        return claripy.Extract(msb, lsb, reg)

    def _update_register_mappings2(self, tainted, tracked, reg_name):
        """
            Map from rdx -> edx -> dx -> dh -> dl 
            updates other aliases from register passed in as reg_name
            if reg_name no longer in taint, it has been killed
        """

        if reg_name in set([ 'ds', 'cs', 'es', 'ss' ]):
            return tainted, tracked

        ##find register name among mappings
        top_regs = list(filter(lambda x: x.name == reg_name, ArchAMD64.register_list))
        if len(top_regs) > 0:
            assert(len(top_regs) == 1)
            reg = top_regs[0]
            for sub_reg in reg.subregisters:
                tracked[sub_reg[0]] = self._extract_subregister(tracked[reg.name], sub_reg)
                if reg.name in tainted:
                    tainted.add(sub_reg[0])

            return tainted, tracked
        else:
            #register is a submapping
            for reg in ArchAMD64.register_list:
                sub_map = list(filter(lambda x: x[0] == reg_name, reg.subregisters))
                if len(sub_map) > 0:
                    assert(len(sub_map) == 1)
                    ##update all subregister values
                    sub_reg_name, sub_reg_start, sub_reg_size = sub_map[0]
                    sub_reg_end = sub_reg_start + (sub_reg_size*8) - 1
                    tracked[reg.name] = self._update_top_register(tracked[reg.name], tracked[sub_reg_name], sub_reg_end, sub_reg_start)
                    if sub_reg_name in tainted:
                        tainted.add(reg.name)

                    for sub_reg in reg.subregisters:
                        tracked[sub_reg[0]] = self._extract_subregister(tracked[reg.name], sub_reg)
                        if reg.name in tainted:
                            tainted.add(sub_reg[0])

                    return tainted, tracked

        #raise RuntimeError("Error cannot find register mapping for {}".format(reg_name))
        self.logger.warning("No register mapping found for {}".format(reg_name))
        return tainted, tracked
                
    def _reg_name_to_size(self, reg_name):

        ##vex special registers
        if reg_name in ['cc_op', 'cc_dep1', 'cc_dep2', 'cc_ndep', 'nraddr', 'd', 'ac', 'fpround', 'ftop', 'cmstart', 'cmlen', 'ip_at_syscall', 
                'idflag', 'emnote', 'sseround', 'fsc3210' ]:
            return 64

        if reg_name[0] == 'r' and reg_name[-1] == 'b':
            return 8
        elif reg_name[0] == 'r' and reg_name[-1] == 'w':
            return 16
        elif reg_name[0] == 'r' and reg_name[-1] == 'd':
            return 32

        if reg_name[0] == 'r':
            return 64
        elif len(reg_name) == 3 and reg_name[0] == 'e':
            return 32
        elif len(reg_name) == 3 and reg_name[1] == 'i' and reg_name[2] in ['l', 'h']:
            ## sil, dil
            return 8
        elif len(reg_name) == 2 and reg_name[1] == 's':
            return 64
        elif len(reg_name) == 2 and reg_name[1] in ['x', 'p', 'i']:
            return 16
        elif len(reg_name) == 2 and reg_name[1] in ['h', 'l']:
            return 8
        elif reg_name[:3] == 'xmm':
            return 128
        elif reg_name[:3] == 'ymm':
            return 256
        elif reg_name[:3] == 'zmm':
            return 512

        ##debug registers
        if reg_name[0] == 'd':
            return 32

        for reg in ArchAMD64.register_list:
            if reg.name == reg_name:
                return 8 * reg.size

        raise RuntimeError("Unknown register size for {}".format(reg_name))


    def _expand_bv_to_reg(self, reg_name, arg):
        l = arg.size()
        d = self._reg_name_to_size(reg_name)

        if d <= l:
            return self._bv_lower_n(arg, d)

        ###register size is greater than arg, 0 extend
        return self._bv_unsigned_ext_to_n(arg, d)
            
            
    def _taint_argument_handle_put_stmt(self, stmt, solver, tainted, tracked):
        in_vars, out_vars = set([]), set([])
        exprs = list(stmt.expressions)

        ##kill register we are storing data in
        out_reg_name = self.irsb.arch.translate_register_name(stmt.offset, stmt.data.result_size(self.irsb.tyenv) // 8)
        tainted = tainted - set([ out_reg_name ])


        """
            I need to ensure consitency between register references e.g. dl -> rdx
        """

        ###TODO updated tracked variable 
        if len(exprs) != 1:
            self.logger.error("Unhandled number of arguments to Put")
            #IPython.embed()
            raise RuntimeError("Unhandled number of arguments to Put")

        #update tracked value
        bv_in = self.get_expr_val(exprs[0], tainted, tracked)
        expanded_bv_in = self._expand_bv_to_reg(out_reg_name, bv_in)
        tracked[ out_reg_name ] = expanded_bv_in


        ##if putting const, kill reg
        if isinstance(exprs[0], pyvex.expr.Get):
            in_reg_name = self.irsb.arch.translate_register_name(stmt.offset, exprs[0].result_size(self.irsb.tyenv) // 8)
            if in_reg_name in tainted:
                tainted.add(out_reg_name)
        elif isinstance(exprs[0], pyvex.expr.RdTmp):
            if exprs[0].tmp in tainted:
                tainted.add(out_reg_name)

        ##update aliasing between rax, ax, ah, al
        tainted, tracked = self._update_register_mappings2(tainted, tracked, out_reg_name)
        #print("Updated reg mappinsg from Put expr")
        #IPython.embed()

        return in_vars, out_vars, tainted, tracked

    def _read_memory(self, tainted, tracked, addr, size_in_bytes):
        """
            Read memory, unknown memory address return symbolic values
        """
        tracked_bytes = [] 
        for i in range(size_in_bytes):
            mkey = 'm_' + str(hex(addr + i))
            if mkey in tracked:
                self.logger.debug("Tracked memory read for {}".format(mkey))
                tracked_bytes.append( tracked[mkey] )
            else:
                self.logger.debug("Address is not tracked: {}".format(hex(addr + i)))
                self.logger.debug("Program must be loading in variables via registers or heap memory. Using symbolic values.")
                #IPython.embed()
                symb_byte = claripy.BVS("symb." + mkey, 8)
                tracked_bytes.append( symb_byte )

        tracked_val = claripy.Concat(*tracked_bytes)
        return tainted, tracked, tracked_val
 
    def _taint_argument_handle_dirty_stmt(self, stmt, solver, tainted, tracked):
        """
            Dirty statements are helpers for CISC instruction such as SHA512, AES funcs
            I can't just making the output symbolic, these helper functions change the CPU state in unknow ways e.g. cpuid puts 
            saves a value into rdi

            I would need to implement taint tracking across all helper functions
        """
        in_vars, out_vars = set([]), set([])
        if hasattr(stmt, 'tmp'):
            size_in_bytes = 8 ##cannot find solid way to get temp value size is bytes, assume 8
            tracked[ stmt.tmp ] = claripy.BVS("symb_addr_val.DIRTY", size_in_bytes*8)
            out_vars.add( stmt.tmp )

        exprs = list(stmt.expressions)
        for expr in exprs:
            in_vars.add( self._expr_name( expr ) )

        return in_vars, out_vars, tainted, tracked

            
    def _taint_argument_handle_cas_stmt(self, stmt, solver, tainted, tracked):
        """
            statement has 2 types, double and single.
            if the value read in from stmt.addr is equal to value in expression 1, set value 
            in address to value in expression 2

            I'm not computing the CAS, just passing taints

            if  (*stmt.addr) == (*expr[1]):
                (*stmt.addr) = expr[2]
        """
        in_vars, out_vars = set([]), set([])
        exprs = list(stmt.expressions)

        out_vars.add( stmt.oldLo )
        #if out_vars.oldHi != '0xffffffff':
        #    out_vars.add(stmt.oldHi)
        #    IPython.embed()
        size_in_bytes = exprs[1].result_size(self.irsb.tyenv) // 8

        for expr in exprs:
            #the value that is moved to addr is condition is true
            if not isinstance(expr, pyvex.expr.Const):
                in_vars.add( self._expr_name( expr ) )

        ##read memory value
        addr1 = self.get_expr_val(exprs[0], tainted, tracked)
        swap_value = self.get_expr_val(exprs[1], tainted, tracked)
        addr2 = self.get_expr_val(exprs[2], tainted, tracked)

        #if address is symbolic, we can't do much
        if addr1.symbolic or addr2.symbolic:
            self.logger.warning("CAS address is symbolic input addresses")
            tracked[ stmt.oldLo ] = claripy.BVS("symb_addr_val.CAS", size_in_bytes*8)
            return in_vars, out_vars, tainted, tracked

        solved_addr1 = solver.eval(addr1, 1)[0]
        solved_addr2 = solver.eval(addr2, 1)[0]
        tainted, tracked, mem_value1 = self._read_memory(tainted, tracked, solved_addr1, size_in_bytes)
        tainted, tracked, mem_value2 = self._read_memory(tainted, tracked, solved_addr2, size_in_bytes)
        tracked[ stmt.oldLo ] = mem_value1
        for i in range(size_in_bytes):
            mkey1 = 'm_' + str(hex(solved_addr1 + i))
            mkey2 = 'm_' + str(hex(solved_addr2 + i))
            in_vars.add( mkey1 )
            in_vars.add( mkey2 )

        ##modify memory based on swap
        cond = (mem_value1 == swap_value)
        if cond.is_true:
            tracked[ stmt.oldLo ] = mem_value2

        return in_vars, out_vars, tainted, tracked

    def _taint_argument_handle_loadg_stmt(self, stmt, solver, tainted, tracked):
        in_vars, out_vars = set([]), set([])
        exprs = list(stmt.expressions)

        ##Taint variable
        out_vars = set([stmt.dst])
        out_var = stmt.dst
        in_vars  = set([])

        out_size = exprs[0].result_size(self.irsb.tyenv)

        #TODO track results of guarded load
        #instead of making symbolic
        tracked[ stmt.dst ] =  claripy.BVS("loadg.symbolic", out_size)

        for expr in exprs:
            in_vars.add( self._expr_name( expr ))

        return in_vars, out_vars, tainted, tracked

    def _taint_argument_handle_geti_stmt(self, stmt, solver, tainted, tracked):
        in_vars, out_vars = set([]), set([])
        exprs = list(stmt.expressions)

        ##Taint variable
        out_vars = set([stmt.tmp])
        out_var = stmt.tmp
        in_vars  = set([])

        out_size = exprs[0].result_size(self.irsb.tyenv)

        #TODO fix temporary implementation
        #instead of making symbolic
        tracked[ stmt.tmp ] =  claripy.BVS("geti.symbolic", out_size)

        for expr in exprs:
            if isinstance(expr, pyvex.expr.RdTmp):
                in_vars.add( self._expr_name( expr ))

        return in_vars, out_vars, tainted, tracked

    def _taint_argument_handle_wrtmp_stmt(self, stmt, solver, tainted, tracked):
        in_vars, out_vars = set([]), set([])
        exprs = list(stmt.expressions)

        ##Taint variable
        out_vars = set([stmt.tmp])
        out_var = stmt.tmp
        in_vars  = set([])

        out_size = exprs[0].result_size(self.irsb.tyenv)

        if len(exprs) == 1:
            if isinstance(exprs[0], pyvex.expr.Get):
                reg_name = self._get_expr_reg(exprs[0].offset, exprs[0]) 
                in_vars = in_vars.union( set([ reg_name ]) )

                val = self.get_expr_val(exprs[0], tainted, tracked)
                tracked[out_var] = val

            ## Get name of temporary variable
            elif isinstance(exprs[0], pyvex.expr.RdTmp):
                in_vars = in_vars.union( self._expr_tmp_args(exprs[0]) )

                val = self.get_expr_val(exprs[0], tainted, tracked)
                tracked[out_var] = val

            elif isinstance(exprs[0], pyvex.expr.Const):
                val = self.get_expr_val(exprs[0], tainted, tracked)
                tracked[out_var] = val

            else:
                self.logger.error("Unhandled single expression statement...")
                self.logger.error(stmt.pp())
                tracked[out_var] = claripy.BVS("unhandled_single_expr", out_size)
                #IPython.embed()
                #raise TypeError("Unhandled single expression statement...")

        elif len(exprs) == 2:
            arg1 = self.get_expr_val(exprs[1], tainted, tracked)

            out_size    = exprs[0].result_size(self.irsb.tyenv)
            in_size     = exprs[1].result_size(self.irsb.tyenv)

            if arg1.size() < in_size:
                arg1 = self._bv_signed_ext_to_n(arg1, in_size)
            if arg1.size() > in_size:
                arg1 = self._bv_lower_n(arg1, in_size)

            ##TODO, make this more generic

            if exprs[0].tag == 'Iex_Binop':
                if 'Not' in exprs[0].op:
                    tracked[out_var] = -arg1
                else:
                    self.logger.error("Statement performed unknown BinOp")
                    self.logger.error(stmt.pp())
                    #IPython.embed()
                    tracked[out_var] = claripy.BVS("unknown_tag::"+ exprs[0].tag, out_size)
                    #raise TypeError("Statement performed unknown BinOp")

            elif exprs[0].tag == 'Iex_Unop':
                """
                    I don't know how vector operations work or the HI encoded
                    ops
                """
                m = re.match(r'^Iop_([V]*)(\d+)([USVHI]*)to([USV]*)(\d+)$', exprs[0].op)
                n = re.match(r'^Iop_Not[V]*(\d+)$', exprs[0].op)
                if m:
                    vector      = m.group(1) == 'V'
                    unsigned    = m.group(3) == 'U'
                    in_base     = int( m.group(2) )
                    out_base    = int( m.group(5) )

                    if out_base <= in_base:
                        tracked[out_var] = self._bv_lower_n(arg1, out_base)
                    elif out_base > in_base:
                        if unsigned:
                            tracked[out_var] = self._bv_unsigned_ext_to_n(arg1, out_base)
                        else:
                            tracked[out_var] = self._bv_signed_ext_to_n(arg1, out_base)
                elif n:
                    tracked[out_var] = -arg1
                else:
                    self.logger.error("Statement performed unknown UnOp")
                    self.logger.error(exprs[0].op)
                    self.logger.error(stmt.pp())
                    #IPython.embed()
                    tracked[out_var] = claripy.BVS("unknown_op::"+ exprs[0].op, out_size)
                    #raise TypeError("Statement performed unknown UnOp")

            elif exprs[0].tag == 'Iex_Load':
                #addr = self.get_expr_val(exprs[0], tainted, tracked)
                addr = self.get_expr_val(exprs[1], tainted, tracked)

                ##assume Load has 1 arg that is a tmp variable
                ##could also be const
                if isinstance(exprs[1], pyvex.expr.RdTmp):
                    in_vars.add( exprs[1].tmp ) 

                if not addr.concrete:
                    #print("Cannot track symbolic load")
                    #IPython.embed()
                    size_in_bits = exprs[0].result_size(self.irsb.tyenv)
                    tracked[out_var] = claripy.BVS('load_from_symbolic_address', size_in_bits)
                    #raise RuntimeError("Cannot track symbolic load")
                else:
                    #evaluate and track memory location
                    size_in_bytes = exprs[0].result_size(self.irsb.tyenv) // 8
                    solved = solver.eval(addr, 1)
                    addr = solved[0]

                    tainted, tracked, mem_value = self._read_memory(tainted, tracked, addr, size_in_bytes)
                    for i in range(size_in_bytes):
                        mkey = 'm_' + str(hex(addr + i))
                        in_vars.add( mkey )

                    tracked[out_var] = mem_value
                    #print("Tracking {}".format(out_var))

            else:
                self.logger.error("Statement performed unknown binary operation")
                self.logger.error(exprs[0].tag)
                self.logger.error(stmt.pp())
                op_name = expers[0].op if hasattr(exprs[0], 'op') else 'unknown'
                tracked[out_var] = claripy.BVS("unknown_op::"+ op_name, out_size)
                #raise TypeError("Statement performed unknown binary operation")

        elif len(exprs) == 3:
            if exprs[0].tag == 'Iex_Binop':
                arg1 = self.get_expr_val(exprs[1], tainted, tracked)
                arg2 = self.get_expr_val(exprs[2], tainted, tracked)

                arg1_size = exprs[1].result_size(self.irsb.tyenv)
                arg2_size = exprs[2].result_size(self.irsb.tyenv)

                ##arguments must be the same size for operations to happend
                in_size = max([arg1_size, arg2_size])

                if arg1.size() < in_size:
                    arg1 = self._bv_signed_ext_to_n(arg1, in_size)
                if arg2.size() < in_size:
                    arg2 = self._bv_signed_ext_to_n(arg2, in_size)
                if arg1.size() > in_size:
                    arg1 = self._bv_lower_n(arg1, in_size)
                if arg2.size() > in_size:
                    arg2 = self._bv_lower_n(arg2, in_size)

                try:
                    ##get value from other expressions
                    if 'Iop_Sub' in exprs[0].op:
                        tracked[out_var] = arg1 - arg2
                    elif 'Iop_Add' in exprs[0].op:
                        tracked[out_var] = arg1 + arg2
                    elif 'Iop_And' in exprs[0].op:
                        tracked[out_var] = arg1 & arg2
                    elif 'Iop_Or' in exprs[0].op:
                        tracked[out_var] = arg1 | arg2
                    elif 'Iop_Xor' in exprs[0].op:
                        tracked[out_var] = arg1 ^ arg2
                    elif 'Iop_Div' in exprs[0].op:
                        tracked[out_var] = arg1 / arg2
                    elif 'Iop_Mod' in exprs[0].op:
                        tracked[out_var] = arg1 % arg2
                    elif 'Iop_Mul' in exprs[0].op:
                        tracked[out_var] = arg1 * arg2
                    elif 'Iop_Shl' in exprs[0].op:
                        if arg2.symbolic:
                            tracked[out_var] = claripy.BVS("symbolic_shl", out_size)
                        else:
                            shift = solver.eval( arg2, 1)[0]
                            zeros = claripy.BVV(0, shift)
                            cc = claripy.Concat(arg1, zeros)
                            tracked[out_var] = claripy.Extract(out_size-1, 0, cc)
                    elif 'Iop_Shr' in exprs[0].op:
                        if arg2.symbolic:
                            tracked[out_var] = claripy.BVS("symbolic_shr", out_size)
                        else:
                            shift = solver.eval( arg2, 1)[0]
                            zeros = claripy.BVV(0, shift)
                            cc = claripy.Concat(zeros, arg1)
                            tracked[out_var] = claripy.Extract(cc.size()-1, shift, cc)
                    elif 'Iop_Sar' in exprs[0].op:
                        tracked[out_var] = arg1 >> arg2
                    elif 'Iop_Sal' in exprs[0].op:
                        tracked[out_var] = arg1 << arg2
                    elif 'CmpGT' in exprs[0].op:
                        cond = (arg1 > arg2)
                        a = claripy.BVV(1, out_size)
                        if cond.is_true():
                            a = claripy.BVV(0, out_size)
                        tracked[out_var] = a
                    elif 'CmpGE' in exprs[0].op:
                        cond = (arg1 >= arg2)
                        a = claripy.BVV(1, out_size)
                        if cond.is_true():
                            a = claripy.BVV(0, out_size)
                        tracked[out_var] = a
                    elif 'CmpLT' in exprs[0].op:
                        cond = (arg1 < arg2)
                        a = claripy.BVV(1, out_size)
                        if cond.is_true():
                            a = claripy.BVV(0, out_size)
                        tracked[out_var] = a
                    elif 'CmpLE' in exprs[0].op:
                        cond = (arg1 <= arg2)
                        a = claripy.BVV(1, out_size)
                        if cond.is_true():
                            a = claripy.BVV(0, out_size)
                        tracked[out_var] = a
                    elif 'CmpEQ' in exprs[0].op:
                        cond = (arg1 == arg2)
                        a = claripy.BVV(1, out_size)
                        if cond.is_true():
                            a = claripy.BVV(0, out_size)
                        tracked[out_var] = a
                    elif 'CmpNE' in exprs[0].op:
                        cond = (arg1 == arg2)
                        a = claripy.BVV(1, out_size)
                        if cond.is_false():
                            a = claripy.BVV(0, out_size)
                        tracked[out_var] = a
                    elif 'HLto' in exprs[0].op:
                        ##concat 2 32 bit numbers into 64 bit
                        tracked[out_var] = claripy.Concat(arg1, arg2)
                    elif 'Interleave' in exprs[0].op:
                        ##concat 2 32 bit numbers into 64 bit
                        tracked[out_var] = self._interleave(out_size, arg1, arg2)
                    elif 'StoF' in exprs[0].op:
                        #I don't know how to do conversion
                        tracked[out_var] = claripy.BVS("StoFconversion", out_size)
                    else:
                        self.logger.error("Statement performed unknown binary operation")
                        self.logger.error(exprs[0].op)
                        self.logger.error(stmt.pp())
                        #IPython.embed()
                        tracked[out_var] = claripy.BVS("unknown_op::"+ exprs[0].op, out_size)
                        #raise Exception("Statement performed unknown binary operation")

                except Exception as e:
                    self.logger.error("exception whilst processing BinOp with 3 args")
                    self.logger.error(e)
                    #IPython.embed()
                    #raise RuntimeError("Exception occoured processing BinOp expression")
                    tracked[out_var] = claripy.BVS("binop_exception"+ exprs[0].op, out_size)

            if isinstance(exprs[0], pyvex.expr.CCall):
                ##cannot compute value statically, need to execute it
                tracked[out_var] = claripy.BVS("ccall", 64)
                for expr in exprs[1:]:
                    in_vars.add( self._expr_name( expr ) )


        #elif len(exprs) > 3:
        else:
            if isinstance(exprs[0], pyvex.expr.CCall):
                ##cannot compute value statically, need to execute it
                tracked[out_var] = claripy.BVS("ccall", 64)
                for expr in exprs[1:]:
                    in_vars.add( self._expr_name( expr ) )

            elif isinstance(exprs[0], pyvex.expr.ITE):
                for expr in exprs[1:]:
                    in_vars.add( self._expr_name( expr ) )
                tracked[out_var] = self.get_expr_val(exprs[2], tainted, tracked) | self.get_expr_val(exprs[3], tainted, tracked)

            else:
                self.logger.error("Error, more that 3 expressions for statement!")
                self.logger.error(exprs[0].tag)
                self.logger.error(stmt.pp())
                #IPython.embed()
                tracked[out_var] = claripy.BVS("unknown_op" + exprs[0].op, out_size)
                #raise Exception("Error, VEX statment has more than 3 expressions! Cannot handle...")

        ###check all tracks vars for NotImplemented
        for k, v in tracked.items():
            if type(v) == type(NotImplemented):
                self.logger.error("Error tracked var {} is of type NotImplemneted".format(k, v))
                #IPython.embed()
                raise RuntimeError("Error tracked var {} is of type NotImplemneted".format(k, v))


        #TODO taint track expression used in WrTmp
        for expr in exprs[1:]:
            in_vars.add( self._expr_name( expr ))

        return in_vars, out_vars, tainted, tracked

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

    def _bv_unsigned_ext_to_n(self, arg, n):
        """ Unsigend extended variable to n bits """
        d = arg.size()
        assert(d <= n)
        return claripy.ZeroExt(n-d, arg)

    def _bv_signed_ext_to_n(self, arg, n):
        """ Signed extended variable to n bits """
        d = arg.size()
        assert(d <= n)
        return claripy.SignExt(n-d, arg)

    def _func_arg_flows_from_taints(self, tainted, tracked, solver):
        flows = []
        tainted_func_args = set([ 'rsi', 'rdi', 'rdx', 'rcx', 'r8', 'r9' ]).intersection(tainted)
        if len(tainted_func_args) > 0:
            """
                We might have a tainted function argument that the callee doesn't
                take as a parameter. Add anyway and then fix up at the end.
            """
            ##find function name of flow
            expr = self.irsb.next
            if isinstance(expr, pyvex.expr.Const):
                vaddr = expr.con.value
                flow = [ self.irsb.addr , vaddr , frozenset(tainted_func_args) ]
                flows.append( flow )
            else:
                #print("We have a non-const func-func flow!")
                #IPython.embed()

                if expr.tmp in tracked:
                    ##if value is concrete
                    if tracked[ expr.tmp ].concrete:
                        solved = solver.eval( tracked[ expr.tmp ], 1)
                        val = solved[0]

                        flow = [ self.irsb.addr , val, frozenset(tainted_func_args) ]
                        flows.append( flow )
                    else:
                        #print("Symbolic flow address, check for multiple conditions, need to add all of them")
                        try:
                            num_possible_values = self._get_cardinality(tracked[ expr.tmp ])
                        except:
                            num_possible_values = math.inf
                        if num_possible_values < 256:
                            solved = solver.eval(addr_target, num_possible_values)
                            for val in solved:
                                flow = [ self.irsb.addr , val, frozenset(tainted_func_args) ]
                                flows.append( flow )
                        else:
                            self.logger.warn("Unbound symbolic expression for flow address - {}. Skipping :(".format(num_possible_values))
        return flows

    def _func_ret_flows_from_taints(self, tainted, tracked, solver):
        flows = []

        #print("Ret jumpkind")
        #IPython.embed()

        tainted_func_args = set([ 'rax', 'xmm0', 'xmm1' ]).intersection(tainted)
        if len(tainted_func_args) > 0:
            #print("POSSIBLE FLOW!!!!!!")
            #IPython.embed()

            flow = [ self.irsb.addr , 'ret' , frozenset(tainted_func_args) ]
            flows.append( flow )

        return flows


    def taint_argument(self, tainted=set([]), tracked=dict({})):
        """
            Context insensitive, taint analysis. Produce map of { arg : [ funcs ] }
            frozenset of [ irsb start vaddr, irsb end vaddr, live tainted vars ]
        """
        solver = claripy.solvers.Solver()
        if self.arch != 'x86_64':
            raise Exception("Error, getting arguments for {} is not currently supported. Only x86_64.".formation(self.arch))


        ##taint/track all input register aliases
        #for reg_name in list(tracked.keys()):
        #    tainted, tracked = self._update_register_mappings2(tainted, tracked, reg_name)

        flows = []
        if isinstance(self.irsb, type(None)):
            return flows, tainted, tracked
            
        #self.irsb.pp()
        for stmt in self.irsb.statements:

            stmt.pp()
            IPython.embed()
            in_vars, out_vars = set([]), set([])

            #or isinstance(stmt, pyvex.stmt.CAS) or isinstance(stmt, pyvex.stmt.LLSC):
            if isinstance(stmt, pyvex.stmt.Store):
                in_vars, out_vars, tainted, tracked = self._taint_argument_handle_store_stmt(stmt, solver, tainted, tracked)

            elif isinstance(stmt, pyvex.stmt.Exit):
                in_vars, out_vars, tainted, tracked = self._taint_argument_handle_exit_stmt(stmt, solver, tainted, tracked)

            #kill registers, never a tmp variable since ssa
            elif isinstance(stmt, pyvex.stmt.Put):
                in_vars, out_vars, tainted, tracked = self._taint_argument_handle_put_stmt(stmt, solver, tainted, tracked)

            elif isinstance(stmt, pyvex.stmt.WrTmp):
                in_vars, out_vars, tainted, tracked = self._taint_argument_handle_wrtmp_stmt(stmt, solver, tainted, tracked)

            elif isinstance(stmt, pyvex.stmt.CAS):
                in_vars, out_vars, tainted, tracked = self._taint_argument_handle_cas_stmt(stmt, solver, tainted, tracked)

            #elif isinstance(stmt, pyvex.stmt.LLSC):
            #elif isinstance(stmt, pyvex.stmt.StoreG):
            elif isinstance(stmt, pyvex.stmt.LoadG):
                in_vars, out_vars, tainted, tracked = self._taint_argument_handle_loadg_stmt(stmt, solver, tainted, tracked)
            elif isinstance(stmt, pyvex.stmt.MBE):
                pass
            elif isinstance(stmt, pyvex.stmt.PutI):
                ##not implemented
                pass
            #elif isinstance(stmt, pyvex.stmt.GetI):
            #    in_vars, out_vars, tainted, tracked = self._taint_argument_handle_geti_stmt(stmt, solver, tainted, tracked)

            elif isinstance(stmt, pyvex.stmt.IMark):
                ##ignore instruction markers
                pass
            elif isinstance(stmt, pyvex.stmt.NoOp):
                ##ignore no ops
                pass
            elif isinstance(stmt, pyvex.stmt.AbiHint):
                ## AbiHint provides specific information about this platforms ABI
                ## e.g. ====== AbiHint(0xt11, 128, t4) ======
                pass
            else:
                self.logger.error("I don't know how to deal with a {}".format(type(stmt)))
                #IPython.embed()
                raise TypeError("I don't know how to deal with a {}".format(type(stmt)))

            ##pass the taint
            ##for each dependent variable
            if len(in_vars.intersection(tainted)) > 0:
                #if dependent variable is tainted, taint output
                for var in out_vars:
                    tainted.add(var)

        ##calculate flows from taints
        #taint func are if we are calling another func

        if self.irsb.jumpkind == 'Ijk_Call':
            flows = self._func_arg_flows_from_taints(tainted, tracked, solver)

        elif self.irsb.jumpkind == 'Ijk_Boring':
            #don't include jumps within same function
            #todo
            flows = self._func_arg_flows_from_taints(tainted, tracked, solver)

        ##taint return registers if we are returning
        elif self.irsb.jumpkind == 'Ijk_Ret':
            flows = self._func_ret_flows_from_taints(tainted, tracked, solver)

        #print("BB tainted.")
        #print("Tainted {}".format(tainted))
        #print("Flows {}".format(flows))

        return flows, tainted, tracked

    def _count_operations(self, operations):
        op_dict = {}
        for op in operations:
            if op not in op_dict:
                op_dict[op] = 1
            else:
                op_dict[op] += 1
        return op_dict

    def _count_tags(self, vex_object_list):
        tag_dict = {}
        for vex_obj in vex_object_list:
            tag = vex_obj.tag
            if tag not in tag_dict:
                tag_dict[tag] = 1
            else:
                tag_dict[tag] += 1
        #tag_list = []
        #for tag in tag_dict:
        #    tag_list.append( [ tag, tag_dict[tag] ] )
        #return tag_list
        return tag_dict

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __hash__(self):
        return hash(self.__dict__)

    def to_json(self):
        return json.dumps( self.to_dict(), sort_keys=True, indent=4)

    ### Must have only string keys
    def to_dict(self):
        dict_obj = { 
            "size"          : copy.deepcopy(self.size),
            "vaddr"         : copy.deepcopy(self.vaddr), 
            "data"          : copy.deepcopy(binascii.hexlify(self.data).decode('ascii')), 
            "vex"           : copy.deepcopy(self.vex), 
            "asm"           : copy.deepcopy(self.asm), 
            "opcodes"       : copy.deepcopy(self.opcodes), 
            "arch"          : copy.deepcopy(self.arch), 
            "hash"          : copy.deepcopy(binascii.hexlify(self.hash).decode('ascii')),
            "opcode_hash"   : copy.deepcopy(binascii.hexlify(self.opcode_hash).decode('ascii')),
        }

        ##convert sets to list to print as json
        if self.vex:
            for k, v in self.vex.items():
                if isinstance(v, set):
                    dict_obj['vex'][k] = list(self.vex[k])
            """
            #for vex_attr in [ "operations", "expressions", "statements" ]:
            for vex_attr in [ "operations" ]:
                if isinstance( dict_obj['vex'][vex_attr], np.ndarray ):
                    dict_obj['vex'][vex_attr] = dict_obj['vex'][vex_attr].tolist() 
                else:
                    dict_obj['vex'][vex_attr] = dict_obj['vex'][vex_attr]
            """

            """ Removed Constants
            #convert tuple to list
            for i in range(len(self.vex['constants'])):
                ##cannot serialise set, converted to list[ TYPE, VALUE ]
                dict_obj['vex']['constants'][i] = list( self.vex['constants'][i] )
            """

            #self.vex['temp_vars'] = dict( self.vex['temp_vars' ] )
        return dict_obj

    @staticmethod
    def from_dict(dict_obj):
        default_bb = { "size" : -1, "vaddr" : -1, "data" : b'', "vex" : None, "asm" : [], "opcodes" : [], "hash": b'', "opcode_hash" : b'' }
        default_bb.update(dict_obj)
        n = default_bb
        return BasicBlock(Config(), size=n['size'], vaddr=n['vaddr'], data=n['data'], vex=n['vex'], asm=n['asm'], opcodes=n['opcodes'], hash=n['hash'], opcode_hash=n['opcode_hash'], arch=n['arch'])

    @staticmethod
    def from_json(json_str):
        dict_obj = json.loads( json_str )
        return BasicBlock.from_dict( dict_obj )

    def __str__(self):
        return self.to_json()


    #Get a measure of similarity between this bb and another
    def similarity(self, other):
        sim = []
        #### Symbol size
        size_sim = self._num_diff(self.size, other.size)
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
            #### VEX Size
            vex_ninstr_sim = self._num_diff(self.vex['ninstructions'], other.vex['ninstructions'])
            sim.append(vex_ninstr_sim)

            #### VEX number temporary variables
            vex_nvars_sim = self._num_diff(self.vex['ntemp_vars'], other.vex['ntemp_vars'])
            sim.append(vex_nvars_sim)

            #### Vex jumpkind
            vex_jmpkind_sim = 1.0 if self.vex['jumpkind'] == other.vex['jumpkind'] else 0.0
            sim.append(vex_jmpkind_sim)

            #### Vex sum statements kind
            for kind in [ "statements", "expressions", "operations" ]:
                kind_a = set( self.vex["sum_" + kind].keys() )
                kind_b = set( other.vex["sum_" + kind].keys() )

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
                        a_kind_vec[i] += self.vex["sum_"+kind][kind_all[i]]
                    if kind_all[i] in kind_b:
                        b_kind_vec[i] += float( other.vex["sum_"+kind][kind_all[i]] )

                dot = float( np.dot(a_kind_vec, b_kind_vec) )
                magnitude = float( np.linalg.norm(a_kind_vec, ord=2) * np.linalg.norm(b_kind_vec, ord=2) )
                #print(dot)
                #print(magnitude)

                if magnitude == 0.0:
                    sim.append(1.0)
                else:
                    #### Floating point rounding errors!!!
                    if abs(dot - magnitude) <= 0.000001:
                        dot = magnitude

                    #assert( float(magnitude) >= float(dot) )
                    vex_kind_sim = math.acos( dot / magnitude )
                    sim.append(1.0 - vex_kind_sim)

            #### Vex constant matching
            # not implemented, from JS implementation this metric is rubbish

        #vex not implemented
        elif not self.vex and not other.vex:
            sim += [1.0] * 9
        else:
            sim += [0.0] * 9

        #### CFG BBS number of callees
        callees_size_sim = self._num_diff( len(self.callees), len(other.callees) )
        sim.append(callees_size_sim)

        logger.debug(list( zip( sim, [
                        "size in bytes", 
                        "hash",
                        "opcode hash",
                        "number of VEX IR instructions",
                        "number of VEX temporary variables", 
                        "VEX jump kind", 
                        "sum_statements -- types",
                        "sum_statements -- vector angle",
                        "sum_epressions -- types",
                        "sum_epressions -- vector angle",
                        "sum_operations -- types",
                        "sum_operations -- vector angle",
        ] ) ) )

        w_sim = np.array( sim )
        return w_sim


    @staticmethod
    def _is_bb_jump(cs_instr, arch):
        """
            Return if condition or unconditional jump
            Also return target address
        """
        target = None
        if CS_GRP_JUMP in cs_instr.groups:
            #print("{} {}".format(cs_instr.mnemonic, cs_instr.op_str))
            target = cs_instr.operands[0].value.reg
            #print( "Target addr: {}".format(target))
        return CS_GRP_JUMP in cs_instr.groups, target

    @staticmethod
    def _is_bb_end(cs_instr, arch):

        #Using capstone group vs capstone instr ids from nucleus
        """
        if len(cs_instr.groups) > 0:
            for g in cs_instr.groups:
                print( g )
                for GRP in [ CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_INT, CS_GRP_IRET ]:
                    if g == GRP:
                        return True

        return False
        """

        if arch == "x86_64":

            #RET | JMP | COND | CFLOW | CALL
            CFLOW_TERMINATORS = set([ X86_INS_INT3, X86_INS_UD2, X86_INS_CALL, X86_INS_LCALL, X86_INS_RET, X86_INS_RETF,
            X86_INS_JMP, X86_INS_JAE, X86_INS_JA, X86_INS_JBE, X86_INS_JB, X86_INS_JCXZ, X86_INS_JECXZ, 
            X86_INS_JE, X86_INS_JGE, X86_INS_JG, X86_INS_JLE, X86_INS_JL, X86_INS_JNE, X86_INS_JNO,
            X86_INS_JNP, X86_INS_JNS, X86_INS_JO, X86_INS_JP, X86_INS_JRCXZ, X86_INS_JS, X86_INS_HLT ])

            if cs_instr.id in CFLOW_TERMINATORS:
                return True

            return False

        elif arch == "ARMv7":
            CFLOW_TERMINATORS = set([
                ARM_INS_B, ARM_INS_BFC, ARM_INS_BFI,
                ARM_INS_BIC, ARM_INS_BKPT, ARM_INS_BL,
                ARM_INS_BLX, ARM_INS_BX, ARM_INS_BXJ
                ])

            if cs_instr.id in CFLOW_TERMINATORS:
                return True
            return False

        elif arch == "PPC64":
            #nucleus cflow terms
            CFLOW_TERMINATORS = set([
                PPC_INS_B,
                PPC_INS_BA,
                PPC_INS_BC,
                PPC_INS_BCA,
                PPC_INS_BL,
                PPC_INS_BLA,
                PPC_INS_BLR,
                PPC_INS_BCL,
                PPC_INS_BCLA,
                PPC_INS_BCTR,
                PPC_INS_BCTRL,
                PPC_INS_BCCTR,
                PPC_INS_BCCTRL
            ])

            ##Branches and traps
            """
            CFLOW_TERMINATORS = set([
                PPC_INS_B, PPC_INS_BA, PPC_INS_BC, PPC_INS_BCA,
                PPC_INS_BCCTR, PPC_INS_BCCTRL, PPC_INS_BCL, PPC_INS_BCLA,
                PPC_INS_BCLR, PPC_INS_BCLRL, PPC_INS_BCTR, PPC_INS_BCTRL,
                PPC_INS_BDNZ, PPC_INS_BDNZA, PPC_INS_BDNZF, PPC_INS_BDNZFA,
                PPC_INS_BDNZFL, PPC_INS_BDNZFLA, PPC_INS_BDNZFLRL, PPC_INS_BDNZL,
                PPC_INS_BDNZLA, PPC_INS_BDNZLR, PPC_INS_BDNZLRL, PPC_INS_BDNZT,
                PPC_INS_BDNZTA, PPC_INS_BDNZTL, PPC_INS_BDNZTLA, PPC_INS_BDNZTLR,
                PPC_INS_BDNZTLRL, PPC_INS_BDZ, PPC_INS_BDZA, PPC_INS_BDZF,
                PPC_INS_BDZFA, PPC_INS_BDZFL, PPC_INS_BDZFLA, PPC_INS_BDZFLR,
                PPC_INS_BDZFLRL, PPC_INS_BDZL, PPC_INS_BDZLA, PPC_INS_BDZLR,
                PPC_INS_BDZLRL, PPC_INS_BDZT, PPC_INS_BDZTA, PPC_INS_BDZTL,
                PPC_INS_BDZTLA, PPC_INS_BDZTLR, PPC_INS_BDZTLRL, PPC_INS_BF,
                PPC_INS_BFA, PPC_INS_BFCTR, PPC_INS_BFCTRL, PPC_INS_BFL,
                PPC_INS_BFLA, PPC_INS_BFLR, PPC_INS_BFLRL, PPC_INS_BL,
                PPC_INS_BLA, PPC_INS_BLR, PPC_INS_BLRL, PPC_INS_BRINC,
                PPC_INS_BT, PPC_INS_BTA, PPC_INS_BTCTR, PPC_INS_BTCTRL,
                PPC_INS_BTL, PPC_INS_BTLA, PPC_INS_BTLR, PPC_INS_BTLRL,
                PPC_INS_TD, PPC_INS_TDEQ, PPC_INS_TDEQI, PPC_INS_TDGT,
                PPC_INS_TDGTI, PPC_INS_TDI, PPC_INS_TDLGT, PPC_INS_TDLGTI,
                PPC_INS_TDLLT, PPC_INS_TDLLTI, PPC_INS_TDLT, PPC_INS_TDLTI,
                PPC_INS_TDNE, PPC_INS_TDNEI, PPC_INS_TDU, PPC_INS_TDUI,
                PPC_INS_TLBIA, PPC_INS_TLBIE, PPC_INS_TLBIEL, PPC_INS_TLBIVAX,
                PPC_INS_TLBLD, PPC_INS_TLBLI, PPC_INS_TLBRE, PPC_INS_TLBREHI,
                PPC_INS_TLBRELO, PPC_INS_TLBSX, PPC_INS_TLBSYNC, PPC_INS_TLBWE,
                PPC_INS_TLBWEHI, PPC_INS_TLBWELO, PPC_INS_TRAP, PPC_INS_TW,
                PPC_INS_TWEQ, PPC_INS_TWEQI, PPC_INS_TWGT, PPC_INS_TWGTI,
                PPC_INS_TWI, PPC_INS_TWLGT, PPC_INS_TWLGTI, PPC_INS_TWLLT,
                PPC_INS_TWLLTI, PPC_INS_TWLT, PPC_INS_TWLTI, PPC_INS_TWNE,
                PPC_INS_TWNEI, PPC_INS_TWU, PPC_INS_TWUI 
            ])
            """

            if cs_instr.id in CFLOW_TERMINATORS:
                return True
            return False


    @staticmethod
    def gen_leaders(data, vaddr, arch):
        assert(len(data) > 0)

        #print("Forming basicblock from data: {}".format(data))

        ARCH, MODE = "", ""
        if arch == "x86_64":
            ARCH = CS_ARCH_X86
            MODE = CS_MODE_64
        elif arch == "x86" or arch == "x86_32":
            ARCH = CS_ARCH_X86
            MODE = CS_MODE_32
        elif arch == "ARMv7":
            ARCH = CS_ARCH_ARM
            MODE = CS_MODE_THUMB
        elif arch == "PPC64":
            ARCH = CS_ARCH_PPC
            MODE = CS_MODE_64
        else:
            print("UNKNOWN ARCH: {}".format(arch))
            assert(False)

        md = Cs(ARCH, MODE)
        md.detail = True #enable advanced details. required!
        size = 0
        for cs_instr in md.disasm( data, vaddr ):
            size += cs_instr.size
            #print(cs_instr)

            jump, target = BasicBlock._is_bb_jump(cs_instr, arch)
            if jump:
                if target:
                    ##jump inside this function
                    if target > vaddr and target < (vaddr + len(data)):
                        yield target
                else:
                    #print("Warning: Non-deterministic jump! Cannot find target address!!")
                    #print("Warning: I SHOULD BE EXTRACTING BASIC BLOCKS FROM IDA PYTHON")
                    yield vaddr + size

            if BasicBlock._is_bb_end(cs_instr, arch):
                yield vaddr + size

        ##add final bb
        yield vaddr + len(data)

    @staticmethod
    def from_data( data, vaddr, arch):
        assert(len(data) > 0)

        #print("Forming basicblock from data: {}".format(data))

        ARCH, MODE = "", ""
        if arch == "x86_64":
            ARCH = CS_ARCH_X86
            MODE = CS_MODE_64
        elif arch == "x86" or arch == "x86_32":
            ARCH = CS_ARCH_X86
            MODE = CS_MODE_32
        elif arch == "ARMv7":
            ARCH = CS_ARCH_ARM
            MODE = CS_MODE_THUMB
        elif arch == "PPC64":
            ARCH = CS_ARCH_PPC
            MODE = CS_MODE_64
        else:
            raise RuntimeError("Error, cannot lift from unknown architecture {}".format(arch))

        md = Cs(ARCH, MODE)
        md.detail = True #enable advanced details. required!
        size = 0
        for cs_instr in md.disasm( data, vaddr ):
            size += cs_instr.size
            #print(cs_instr)
           
            if BasicBlock._is_bb_end(cs_instr, arch):
                return BasicBlock(Config(), size=size, vaddr=vaddr, data=data[:size], arch=arch)

        if size == 0:
            #no instructions decoded, basicblock may overlap?
            #return BasicBlock(Config(), size=size, vaddr=vaddr, data=b'', arch=arch)
            raise NoNativeInstructionsError(data, vaddr, arch)

        #print("{}::{} BasicBlock created with no terminator!".format(__file__, __name__))
        #print("vaddr: {}, data: {}".format(vaddr, data))
        return BasicBlock(Config(), size=size, vaddr=vaddr, data=data[:size], arch=arch)

class VEXLiftingError(RuntimeError):
    def __init__(self, vex_size, bb_size, data):
        self.stderror = "VEX SIZE: {}, BB SIZE: {}, DATA: {}".format(vex_size, bb_size, data)
        self.vex_size = vex_size
        self.bb_size = bb_size
        self.data = data


class NoNativeInstructionsError(RuntimeError):
    def __init__(self, data, vaddr, arch):
        self.stderror   = "No native instruction decoding for basicblock:\
                {} at vaddr: {} for arch: {}".format(data, vaddr, arch)
        self.data       = data
        self.vaddr      = vaddr
        self.arch       = arch



class TaintTracking(BasicBlock):
    """
        Perform taint tracking for a basicblock
    """
    def __init__(self, config, bb):
        classes.utils._desyl_init_class_(self, config)

        self.bb = bb

        #copy irsb from bb
        if hasattr(bb, 'irsb'):
            self.bb.irsb = bb.irsb

        if not self.bb.irsb:
            self.logger.info("VEX IRSB is missing - Re-lifting and generating VEX IR...")
            print(hex(bb.vaddr))
            IPython.embed()
            self.bb._gen_vex()

    def taint(self, tainted, resolved=None):
        """
            Takes in a set of tainted variables
            Outputs a new set of tainted variables
        """
        tainted = copy.deepcopy(tainted)
        for i, stmt in enumerate(self.bb.irsb.statements):
            in_vars, out_vars = set([]), set([])

            ##writing to reg
            if isinstance(stmt, pyvex.stmt.Put):
                out_reg_name = self.bb.irsb.arch.translate_register_name(stmt.offset,
                    stmt.data.result_size(self.bb.irsb.tyenv) // 8)
                try:
                    out_vars.add(LiveVariables.base_reg_name(out_reg_name))
                except Exception as e:
                    self.logger.error(e)
                    continue

            if isinstance(stmt, pyvex.stmt.WrTmp):
                out_vars.add("t{}".format(stmt.tmp))

            if isinstance(stmt, pyvex.stmt.CAS):
                if hex(stmt.oldHi) != "0xffffffff":
                    print("Cannot handle oldHi CAS")
                    IPython.embed()

                out_vars.add("t{}".format(stmt.oldLo))

            if isinstance(stmt, pyvex.stmt.Dirty):
                if hasattr(stmt, 'tmp'):
                    out_vars.add("t{}".format(stmt.tmp))

            ##writing to memory loc
            if isinstance(stmt, pyvex.stmt.Store):
                if isinstance(stmt.addr, pyvex.expr.RdTmp):
                    resKey = "bb{}_t{}".format(self.bb.vaddr, stmt.addr.tmp)
                    if resolved and resKey in resolved and resolved[resKey]:
                        out_vars.add("mem_{}".format(hex(resolved[resKey])))
                    else:
                        #print("Check resolved for bb{}_t{}".format(self.bb.vaddr, stmt.addr.tmp))
                        #IPython.embed()
                        out_vars.add("mem_bb{}_t{}".format(self.bb.vaddr, stmt.addr.tmp))
                elif isinstance(stmt.addr, pyvex.expr.Const):
                    out_vars.add("mem_{}".format(hex(stmt.addr.con.value)))

            ##for all statements, not just put statements
            for expr in stmt.expressions:
                if expr.tag == 'Iex_Get':
                    reg_name = self.bb.irsb.arch.translate_register_name(expr.offset, expr.result_size(self.bb.irsb.tyenv) // 8)
                    try:
                        in_vars.add(LiveVariables.base_reg_name(reg_name))
                    except Exception as e:
                        self.logger.error(e)
                        continue

                if expr.tag == 'Iex_Load':
                    if isinstance(expr.addr, pyvex.expr.RdTmp):
                        resKey = "bb{}_t{}".format(self.bb.vaddr, expr.addr.tmp)
                        if resolved and resKey in resolved and resolved[resKey]:
                            in_vars.add("mem_{}".format(hex(resolved[resKey])))
                        else:
                            #print("Check resolved for bb{} Exp Load".format(self.bb.vaddr, expr.addr.tmp))
                            #IPython.embed()
                            in_vars.add("mem_bb{}_t{}".format(self.bb.vaddr, expr.addr.tmp))

                    elif isinstance(expr.addr, pyvex.expr.Const):
                        in_vars.add("mem_{}".format(hex(expr.addr.con.value)))

                if isinstance(expr, pyvex.expr.RdTmp):
                    in_vars.add("t{}".format(expr.tmp))

            #print("in_vars: {}".format(in_vars))
            #print("out_vars: {}".format(out_vars))
            #IPython.embed()
            if len(tainted & in_vars) > 0:
                tainted |= out_vars
            else:
                tainted -= out_vars

        return tainted

class LiveVariables(BasicBlock):
    """
        To find function arguments, find live variables from the entry
        point of the program
    """
    def __init__(self, config, bb, V=None):
        classes.utils._desyl_init_class_(self, config)

        self.bb = bb

        #copy irsb from bb
        if hasattr(self.bb, 'irsb'):
            self.bb.irsb = self.bb.irsb

        if not self.bb.irsb:
            self.logger.info("VEX IRSB is missing - Re-lifting and generating VEX IR...")
            print(hex(self.bb.vaddr))
            IPython.embed()
            self.bb._gen_vex()

        self.V = V
        if not V:
            #self.V = self.gen_all_variables()
            self.V = set([])

    def gen_all_variables(self, resolved_variables=None):
        """
            Generate a set of variables used in the basicblock
        """
        #vex_vars = set(map(lambda i: "t{}".format(i),
        #    range(len(self.irsb.tyenv.types))))

        reg_vars, mem_vars  = set([]), set([])

        for i, stmt in enumerate(self.bb.irsb.statements):
            ##writing to reg
            if isinstance(stmt, pyvex.stmt.Put):
                out_reg_name = self.bb.irsb.arch.translate_register_name(stmt.offset,
                    stmt.data.result_size(self.bb.irsb.tyenv) // 8)
                try:
                    base_reg_name = "reg_bb{}_{}_{}".format(self.bb.vaddr, i, LiveVariables.base_reg_name(out_reg_name))
                    reg_vars.add(base_reg_name)
                except Exception as e:
                    self.logger.error(e)
                    continue

                if resolved_variables:
                    # need to update resolved with tmp or const value
                    expr = list(stmt.expressions)[0]
                    if hasattr(expr, 'tmp'):
                        resolved_variables[out_reg_name] = resolved_variables[expr.tmp]
                    if hasattr(expr, 'value'):
                        resolved_variables[out_reg_name] = expr.value

            ##writing to memory loc
            if isinstance(stmt, pyvex.stmt.Store):
                if isinstance(stmt.addr, pyvex.expr.RdTmp):
                    if resolved_variables and stmt.addr.tmp in resolved_variables and isinstance(resolved_variables[stmt.addr.tmp], int):
                        val = resolved_variables[stmt.addr.tmp]
                        mem_addr = "mem_{}".format(hex(val))
                        mem_vars.add(mem_addr)

                        # need to update resolved with tmp or const value
                        expr = list(stmt.expressions)[0]
                        if hasattr(expr, 'tmp'):
                            resolved_variables[mem_addr] = resolved_variables[expr.tmp]
                        if hasattr(expr, 'value'):
                            resolved_variables[mem_addr] = expr.value
                        if hasattr(expr, 'con'):
                            resolved_variables[mem_addr] = expr.con.value
                    else:
                        mem_vars.add("mem_bb{}_t{}".format(self.bb.vaddr, stmt.addr.tmp))
                elif isinstance(stmt.addr, pyvex.expr.Const):
                    mem_addr = "mem_{}".format(hex(stmt.addr.con.value))
                    mem_vars.add(mem_addr)

                    if resolved_variables:
                        expr = list(stmt.expressions)[0]
                        if hasattr(expr, 'tmp'):
                            resolved_variables[mem_addr] = resolved_variables[expr.tmp]
                        if hasattr(expr, 'value'):
                            resolved_variables[mem_addr] = expr.value
                        if hasattr(expr, 'con'):
                            resolved_variables[mem_addr] = expr.con.value

            ##for all statements, not just put statements
            for expr in stmt.expressions:
                if expr.tag == 'Iex_Get':
                    reg_name = self.bb.irsb.arch.translate_register_name(expr.offset, expr.result_size(self.bb.irsb.tyenv) // 8)
                    try:
                        base_reg_name = "reg_bb{}_{}_{}".format(self.bb.vaddr, i, LiveVariables.base_reg_name(reg_name))
                        reg_vars.add(base_reg_name)
                    except Exception as e:
                        self.logger.error(e)
                        continue


                if expr.tag == 'Iex_Load':
                    if isinstance(expr.addr, pyvex.expr.RdTmp):
                        if resolved_variables and expr.addr.tmp in resolved_variables and isinstance(resolved_variables[expr.addr.tmp], int):
                            val = resolved_variables[expr.addr.tmp]
                            mem_vars.add("mem_{}".format(hex(val)))
                        else:
                            mem_vars.add( "mem_bb{}_t{}".format(self.bb.vaddr, expr.addr.tmp) ) 
                    elif isinstance(expr.addr, pyvex.expr.Const):
                        mem_vars.add("mem_{}".format(hex(expr.addr.con.value)))

        #return vex_vars.union(reg_vars.union(mem_vars))
        return reg_vars.union(mem_vars)

    def kill_variable(self, var):
        if var in self.V:
            self.V.remove(var)

    def gen_variable(self, var):
        self.V.add(var)

    @staticmethod
    def base_reg_name(reg_name):
        for reg in ArchAMD64.register_list:
            if reg.name == reg_name:
                return reg.name

            if hasattr(reg, 'alias_names') and reg_name in reg.alias_names:
                return reg.name

            if hasattr(reg, 'subregisters'):
                for sr_name, sr_start, sr_size in reg.subregisters:
                    if sr_name == reg_name:
                        return reg.name

        raise RuntimeError("Unknown base register for register: {}".format(reg_name))


    def data_dependencies(self):
        """
        Compute the set of variables a variable is data-dependent on
        :param V: The constraint variable ||v||. The set of variables that are
                live before the basicblock is executed
        """
        #vex_vars = set(map(lambda i: "t{}".format(i), range(len(self.bb.irsb.tyenv.types))))
        ##state of all variables and dependencies
        #state = { v: set([]) for v in vex_vars }
        state = {}


        #fix register alias dependencies

        for i, stmt in enumerate(self.bb.irsb.statements):
            vex_var2 = None

            ##writing to reg
            if isinstance(stmt, pyvex.stmt.WrTmp):
                vex_var     = "t{}".format(stmt.tmp)
            elif isinstance(stmt, pyvex.stmt.CAS):
                if hex(stmt.oldHi) != "0xffffffff":
                    vex_var2     = "t{}".format(stmt.oldHi)
                vex_var     = "t{}".format(stmt.oldLo)
            elif isinstance(stmt, pyvex.stmt.LoadG):
                vex_var     = "t{}".format(stmt.dst)
            elif isinstance(stmt, pyvex.stmt.Dirty):
                if not hasattr(stmt, 'tmp'):
                    continue
                vex_var     = "t{}".format(stmt.tmp)
            elif isinstance(stmt, pyvex.stmt.Put):
                reg_name    = self.bb.irsb.arch.translate_register_name(stmt.offset, stmt.data.result_size(self.bb.irsb.tyenv) // 8)
                try:
                    vex_var     = "reg_bb{}_{}_{}".format(self.bb.vaddr, i, LiveVariables.base_reg_name(reg_name))
                except Exception as e:
                    self.logger.error(e)
                    continue
            else:
                continue

            dependants  = set([])

            ##for all statements, not just put statements
            for expr in stmt.expressions:
                if expr.tag == 'Iex_RdTmp':
                    dependants.add("t{}".format(expr.tmp))

                if expr.tag == 'Iex_Get':
                    try:
                        reg_name = self.bb.irsb.arch.translate_register_name(expr.offset, expr.result_size(self.bb.irsb.tyenv) // 8)
                        base_reg_name = "reg_bb{}_{}_{}".format(self.bb.vaddr, i, LiveVariables.base_reg_name(reg_name))
                        #dep_reg_name = self._resolve_register(base_reg_name, state)
                        #dependants.add(dep_reg_name)
                        dependants.add(base_reg_name)
                    except Exception as e:
                        self.logger.error(e)
                        continue

                if expr.tag == 'Iex_Load':
                    if isinstance(expr.addr, pyvex.expr.RdTmp):
                        dependants.add("t{}".format(expr.addr.tmp))

                    elif isinstance(expr.addr, pyvex.expr.Const):
                        var = "mem_{}".format(hex(expr.addr.con.value))
                        dependants.add(var)

            state[vex_var] = dependants
            if vex_var2:
                state[vex_var2] = copy.deepcopy(dependants)

        return self.propagate_data_deps(state)

    def _resolve_register(self, reg_name, state):
        """
            Resolve value of register from previous definition
        """
        reg_re = re.compile(r'reg_bb(\d+)_(\d+)_(.+)')
        m = re.match(reg_re, reg_name)
        if not m:
            print("errr 123")
            IPython.embed()
            raise RuntimeError('Error matching register name')

        bb              = int(m.group(1))
        stmt_def_ind    = int(m.group(2))
        reg             = m.group(3)

        ##search for previous definition of reg_name
        prev_defs_re = re.compile(r'reg_bb\d+_(\d+)_{}'.format( reg ))
        highest = 0
        for h_var in filter(lambda x, re=re, c=prev_defs_re: re.match(c, x), state.keys()):
            h = re.match(prev_defs_re, h_var)
            ind = int(h.group(1))

            if ind >= stmt_def_ind:
                continue

            if ind > highest:
                highest = ind

        return "reg_bb{}_{}_{}".format(self.bb.vaddr, highest, reg)

    def propagate_data_deps(self, state):
        """
            Propagates data dependencies for a list of variables
            Will return a full set of varaibels each variable is data dependant
            on
        """
        worklist = collections.deque(state.keys())

        vex_var_re  = re.compile(r't\d+')
        reg_re      = re.compile(r'reg_bb(\d+)_(\d+)_(.+)')
        changed     = True

        while changed:
            changed = False
            for var in list(state.keys()):
                for d_var in set(state[var]):

                    ##if dependant on another tmp var
                    if re.match(vex_var_re, d_var):
                        ##propagate dependency
                        if var not in state or d_var not in state:
                            print("Missing var in tracked state")
                            IPython.embed()
                        if state[var] >= state[d_var]:
                            continue

                        state[var] = state[var] | state[d_var]
                        changed = True

                    """
                    ##register dependencies, may not have a definition
                    m = re.match(reg_re, d_var)
                    if m:
                        if d_var in state:
                            ##propagate dependency
                            if state[var] >= state[d_var]:
                                continue

                            state[var] = state[var] | state[d_var]
                            changed = True

                        prev_def = self._resolve_register(d_var, state)
                        if prev_def in state:
                            state[var] = state[var] | state[prev_def]
                            changed = True
                        else:
                            state[var].add(prev_def)
                    """

        return state

    def live_memory_dependencies(self, index=0):
        """
            List of all variables that depend on live variable from index
        """
        mem_read_lv_re = re.compile(r'mem_bb\d+_t(\d+)')
        tmp_lv = set(filter(lambda x: re.match(mem_read_lv_re, x),
            self.live_variables(index=index)))

        self.logger.debug("Live memory reads from index {} : {}".format(index,
            tmp_lv))

        data_dependencies       = self.data_dependencies()
        live_data_dependencies  = set([])

        for name in tmp_lv:
            m = re.match(mem_read_lv_re, name)
            assert(m)
            ind = m.group(1)
            key = "t{}".format(ind)
            assert(key in data_dependencies.keys())
            live_data_dependencies.add(key)
            live_data_dependencies |= data_dependencies[key]

        return live_data_dependencies

    def memory_dependencies(self, index=0):
        """
            List of all variables that depend on variable from index
        """
        mem_read_lv_re = re.compile(r'mem_bb\d+_t(\d+)')
        tmp_lv = set(filter(lambda x: re.match(mem_read_lv_re, x),
            self.gen_all_variables()))

        self.logger.debug("memory reads from index {} : {}".format(index,
            tmp_lv))

        data_dependencies       = self.data_dependencies()
        mem_data_dependencies  = set([])

        for name in tmp_lv:
            m = re.match(mem_read_lv_re, name)
            assert(m)
            ind = m.group(1)
            key = "t{}".format(ind)
            assert(key in data_dependencies.keys())
            mem_data_dependencies.add(key)
            mem_data_dependencies |= data_dependencies[key]

        return mem_data_dependencies

    def register_dependencies(self, index=0):
        """
            List of all variables that depend on a register put from index
        """
        reg_re = re.compile(r'reg_bb(\d+)_(\d+)_(.+)')
        tmp_lv = set(filter(lambda x: re.match(reg_re, x),
            self.gen_all_variables()))

        self.logger.debug("register variables: {}".format(tmp_lv))

        data_dependencies       = self.data_dependencies()
        reg_data_dependencies  = set([])

        for name in tmp_lv:
            m = re.match(reg_re, name)
            assert(m)
            bb  = m.group(1)
            ind = m.group(2)
            reg_name = m.group(3)
            key = "reg_bb{}_{}_{}".format(bb, ind, reg_name)

            reg_data_dependencies.add(key)
            if key in data_dependencies:
                reg_data_dependencies |= data_dependencies[key]

        return reg_data_dependencies

    def constant_propagation(self, see):
        """
            Symbolic Execution Engine (with a machine_state) and executes statements computing
            addresses of variables that are used to load memory
        """
        tmp_re = re.compile(r't\d')
        live_deps = set(map(lambda x: int(x[1:]) if re.match(tmp_re, x) else x,
            self.memory_dependencies() | self.register_dependencies()))
        self.logger.debug("Removed naming convention for VEX tmp vars. New vars: {}".format(live_deps))
        data_deps = self.data_dependencies()

        see.execute_basicblock_slice(self.bb, live_deps)

        resolved = {}
        for i in filter(lambda x: isinstance(x, int), see.machine_state):
            resolved["bb{}_t{}".format(self.bb.vaddr, i)] = see.resolve_value_concrete(see.machine_state[i], CONCRETE_ONLY=True)

        for var in live_deps:
            if var not in see.machine_state and str(var[:4]) == "mem_":
                if var[4:6] == "0x":
                    see.machine_state[var] = see._read_memory(int(var[6:], 16), 8)
                elif var[4:6] == "bb":
                    print("resolve memory read address")
                    IPython.embed()

            resolved[var] = see.resolve_value_concrete(see.machine_state[var], CONCRETE_ONLY=True)

        return resolved

    def live_variables(self, index=0, resolved_variables=None):
        """
        Compute the live variables from statement at index (default=0)
        :param V: The constraint variable ||v||. The set of variables that are
                live before the basicblock is executed
        :param index: Live from index in vex statements
        """
        ##only track lv entry/exit on memory/registers
        lv_gen, lv_kill = set([]), set([])

        ##backwards analysis, reverse statements
        for stmt in self.bb.irsb.statements[index:][::-1]:
            ##writing to reg
            if isinstance(stmt, pyvex.stmt.Put):
                out_reg_name = self.bb.irsb.arch.translate_register_name(stmt.offset,
                        stmt.data.result_size(self.bb.irsb.tyenv) // 8)
                try:
                    base_reg = LiveVariables.base_reg_name(out_reg_name)
                    self.kill_variable(base_reg)
                except Exception as e:
                    self.logger.error(e)
                    continue

            # writing to memory loc
            if isinstance(stmt, pyvex.stmt.Store):
                if isinstance(stmt.addr, pyvex.expr.RdTmp):
                    resKey = "bb{}_t{}".format(self.bb.vaddr, stmt.addr.tmp)
                    if resolved_variables and resKey in resolved_variables and resolved_variables[resKey]:
                        self.kill_variable("mem_{}".format(hex(resolved_variables[resKey])))
                    else:
                        self.kill_variable("mem_{}".format(resKey))
                elif isinstance(stmt.addr, pyvex.expr.Const):
                    self.kill_variable("mem_{}".format(hex(stmt.addr.con.value)))

            ##for all statements, not just put statements
            for expr in stmt.expressions:
                if expr.tag == 'Iex_Get':
                    reg_name = self.bb.irsb.arch.translate_register_name(expr.offset, expr.result_size(self.bb.irsb.tyenv) // 8)
                    try:
                        base_reg = LiveVariables.base_reg_name(reg_name)
                        self.gen_variable(base_reg)
                    except Exception as e:
                        self.logger.error(e)
                        continue

                if expr.tag == 'Iex_Load':
                    if isinstance(expr.addr, pyvex.expr.RdTmp):
                        resKey = "bb{}_t{}".format(self.bb.vaddr, expr.addr.tmp)
                        if resolved_variables and resKey in resolved_variables and resolved_variables[resKey]:
                            self.gen_variable("mem_{}".format(hex(resolved_variables[resKey])))
                        else:
                            self.gen_variable("mem_{}".format(resKey))

                    elif isinstance(expr.addr, pyvex.expr.Const):
                        var = "mem_{}".format(hex(expr.addr.con.value))
                        self.gen_variable(var)

        return self.V
