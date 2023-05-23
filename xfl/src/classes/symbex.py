import context
import classes.utils
from classes.config import Config

import angr
import claripy
from angr import options as so

import IPython
import logging

class SymbEx():
        def __init__(self, config, binary):
                """
                Class for performing symbolic execution using ANGR
                """
                classes.utils._desyl_init_class_(self, config)
                self.b = binary

                self.proj       = angr.Project(self.b.path, load_options={'auto_load_libs':False})
                self.main_obj   = self.proj.loader.main_object
                self.base       = self.main_obj.mapped_base

                #fix for loading binaries
                if self.proj.loader.main_object.pic:
                    self.base_vaddr = self.base
                else:
                    self.base_vaddr = 0

                logging.getLogger('angr.manager').setLevel(logging.DEBUG)

        """
        @staticfunction
        def _until(state):

                func_calls=lambda x: x.history.jumpkind in [ 'Ijk_Call', 'Ijk_Boring' ] \
                        and x.addr >= start_addr and x.addr <= end_addr

                func_end=lambda x: x.history.jumpkind == 'Ijk_Ret' \
                        and x.addr < start_addr and x.addr > end_addr
                
                pass
        """

        def rda(self, s):
            f = self.proj.loader.find_symbol( s.name )
            self.RDA = ReachingDefinitionAnalysis( f, track_tmps=True )
            print(self.RDA)
            IPython.embed()


        def exec_func(self, s):
                simgr = self.proj.factory.simulation_manager()
                start_addr = self.base_vaddr + s.vaddr

                end_addr = start_addr + s.size
                self.logger.debug("Executing function between {} and {}".format(hex(start_addr), hex(end_addr)))
        
                #symb_args = [start_addr]
                symb_args = []
                for arg in range(s.num_args):
                        tmp_arg = claripy.BVS('arg_{}'.format(arg), 64)
                        self.logger.debug("\tCreating symbolic argument {}".format(arg))        
                        symb_args.append(tmp_arg)
                state = self.proj.factory.call_state(start_addr, *symb_args)

                """
                state = self.proj.factory.full_init_state(addr=start_addr)
                arg_map = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
                for arg in range(s.num_args):
                        reg_name = arg_map[arg]
                        state.registers.make_symbolic('symbolic_' + reg_name, reg_name) 
                """


                ##avoid when previous bb was returning and previous bb was in function we are in
                func_ret=lambda x: x.history.jumpkind == 'Ijk_Ret' and x.history.addr >= start_addr and x.history.addr < end_addr

                #find functions that this function calls, note VEX has no Ijk_Jump, just Ijk_Call
                func_calls=lambda x: x.history.jumpkind in [ 'Ijk_Call', 'Ijk_Boring' ] \
                        and x.addr < start_addr and x.addr > end_addr

                out_of_func=lambda x: x.addr < start_addr or x.addr > end_addr
                in_func=lambda x: x.addr >= start_addr and x.addr <= end_addr

                #simgr.explore(find=func_calls,avoid=func_ret, num_states=3, n=10)
                #simgr.explore(find=out_of_func, num_states=5, n=20)
                self._rec_exec_func_state(state, out_of_func, in_func, symb_args, 10)

        def _rec_exec_func_state(self, state, out_of_func, in_func, symb_args, n):
                """
                    Recursively find traversals through states with a 
                    maximum depth of N
                """
                if n == 0:
                    return
                
                simgr = self.proj.factory.simulation_manager(state)
                simgr.explore(find=out_of_func, n=100)

                #print(simgr)
                #IPython.embed()

                ##remove uneeded states
                simgr.move(from_stash='found', to_stash='returned', filter_func=SymbEx.action_out_of_func)


                for _state in simgr.returned:
                    print("=== RET STATE ===")
                    ret_val = claripy.backends.concrete.convert(_state.regs.rax).value
                    print("\tRAX: {}".format(ret_val))

                    for arg in symb_args:
                        arg_val = _state.solver.eval(arg, cast_to=int) 
                        print("\t{}: {}".format(arg, arg_val))

                for _state in simgr.found:
                    print("=== CALL STATE ===")
                    call_name_it = self.b.vaddr_to_name_tree.at(_state.addr - self.base_vaddr) 
                    call_name = next(iter(call_name_it)).data if len(call_name_it) > 0 else "UNKNOWN"
                    print("Called function {} at address {} under conditions:".format(call_name, hex(_state.addr)))
                    for arg in symb_args:
                        arg_val = _state.solver.eval(arg, cast_to=int) 
                        print("\t{}: {}".format(arg, arg_val))


                    out_simgr = self.proj.factory.simulation_manager(_state)
                    out_simgr.explore(find=in_func, n=100)
                    #out_simgr.move(from_stash='found', to_stash='deadended', filter_func=action_in_func)

                    for _in_state in out_simgr.found:
                        self._rec_exec_func_state(_in_state, out_of_func, in_func, symb_args, n-1)

                ##don't ignore active states
                for _state in simgr.active:
                    self._rec_exec_func_state(_state, out_of_func, in_func, symb_args, n)

        @staticmethod
        def action_in_func(_state):
            return False

        @staticmethod
        def action_out_of_func(_state):
            #print("=== STATE ===")

            #for arg in symb_args:
            #    arg_val = _state.solver.eval(arg, cast_to=int) 
            #    print("\t{}: {}".format(arg, arg_val))

            if _state.history.jumpkind == 'Ijk_Ret':
                #print("We are returning from function")
                #get return value
                #return value needs to be in rax
                #IPython.embed()
                #ret_val = claripy.backends.concrete.convert(_state.regs.rax).value
                #print("\tRET: {}".format(ret_val))

                ##do not continue this state
                return True

            if _state.history.jumpkind == 'Ijk_Call':
                #print("We called a function")
                #print("\tADDR: {}".format(_state.addr))
                pass

            if _state.history.jumpkind == 'Ijk_Boring':
                #print("We jumped to a function")
                #IPython.embed()
                #print("\tADDR: {}".format(_state.addr))
                pass

            return False
