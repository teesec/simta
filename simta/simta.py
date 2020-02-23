#!/usr/bin/env python3
import argparse
import angr, claripy
import struct
from utils import get_context
import signal
import os


class SimTA:
    LOGDIR = "./log"
    ERRORLOG = "error.log"

    def __init__(self, ta_binary, lifecycle_entry, tee_lib_binary, call_sequence_module, breakpoints):

        self.base_address = 0x119e000
        self.globaltask_address = self.base_address - 0x15e000
        self.stack_base = 0x11b8000
        self.stack_size = 0x3000 + 8
        self.heap_base = 0x11b4000
        self.heap_size = 0x3000
        self.shared_mem_base = 0xc8020000
        self.shared_mem_sz = 0x3000
        self.breakpoints = [self.base_address + bp for bp in breakpoints]

        self.lifecycle_entry = lifecycle_entry
        self.proj = angr.Project(ta_binary, main_opts={'base_addr': self.base_address},
                                 auto_load_libs=False,
                                 force_load_libs=(tee_lib_binary,),
                                 lib_opts={
                                     'globaltask.elf': {
                                         'base_addr': self.globaltask_address,
                                         'force_rebase': True
                                     }
                                 })
        entry = self.proj.loader.main_object.min_addr + self.lifecycle_entry  # adding main object's base
        self.initial_state = self.proj.factory.entry_state(addr=entry)
        self.init_state(self.initial_state)

        self.initial_state.globals["call_sequence_module"] = call_sequence_module
        self.initial_state.globals['all_symbolics'] = {}
        self.initial_state.globals['state_symbolics'] = ""
        self.initial_state.globals['simta'] = self

        self.install_hooks(self.proj)

        self.simgr = self.proj.factory.simgr(self.initial_state)

        self.state = None
        self.inspect_simgr = None

        if os.path.exists(os.path.join(SimTA.LOGDIR, SimTA.ERRORLOG)):
            os.remove(os.path.join(SimTA.LOGDIR, SimTA.ERRORLOG))

        signal.signal(signal.SIGINT, self.sigint_handler)

    def __str__(self):
        if len(self.simgr.active) > 0:
            if self.state is None:
                return get_context(self.proj, self.simgr.active[0])
            return get_context(self.proj, self.inspect_simgr.active[0])
        else:
            return "No active states."

    def killmyself(self):
        suicide = """
                         ,-------.                 /
                       ,'         `.           ,--'
                     ,'             `.      ,-;--        _.-
               pow! /                 \ ---;-'  _.=.---''
  +-------------+  ;    X        X     ---=-----'' _.-------
  |    -----    |--|                   \-----=---:i-
  +XX|'i:''''''''  :                   ;`--._ ''---':----
  /X+-)             \   \         /   /      ''--._  `-
 .XXX|)              `.  `.     ,'  ,'             ''---.
   X\/)                `.  '---'  ,'                     `-
     \                   `---+---'
      \                      |
       \.                    |
         `-------------------+
        """
        print(suicide)
        os.system('kill %d' % os.getpid())

    def sigint_handler(self, signum, frame):
        """should be helpful when using run()-method"""
        print('Stopping Execution for Debug. If you want to kill the program issue: killmyself()\nTo explore current '
              'states, check self.simgr.active and select the state you are interested in')
        import ipdb; ipdb.set_trace()
        self.killmyself()

    def run(self):
        # TODO: find solution to follow all paths
        # currently we only follow the first possibility (self.simgr.active[0]) (or at least i think so...)
        # or maybe we follow all paths, but we only check pc for the first possibility <- this seems to be the case...
        # any ideas on this are very welcome... :)
        pc = 0x0
        while True:
            self.step()
            if len(self.simgr.active) > 0:
                for state in self.simgr.active:
                    pc = state.solver.eval(state.regs.r15)
                    """
                    if one of the states reaches 'uart_printf_func', it is moved to the deadended stash automatically, 
                    because the uart_printf_func won't return
                    """
                    if pc in self.breakpoints:
                        """
                        if one of the states reaches a breakpoint, we drop an ipdb shell where the analyst can work on 
                        a copy of that state. when the analyst is done and continues execution, execution will continue 
                        at the breakpoint
                        """
                        # NOTE: this is still a sketchy solution, since we might get the same problem we solved here in
                        # the ipdb-analyst mode
                        self.state = state.copy()
                        self.inspect_simgr = self.proj.factory.simgr(self.state)
                        print(self)
                        import ipdb;
                        ipdb.set_trace()
                        self.state = None
                        self.inspect_simgr = None

            else:
                print("No active states.")
                # throws error, because we can not get the symbolic variables from
                # the globals-dict, if we have no active state
                # self.print_input_dependent_errors()
                self.print_interesting_errors()
                break

    def run_explore(self):
        backup = self.state.copy()
        for bp in self.breakpoints:
            print("BREAKPOINT TO LOOK FOR:", hex(bp))
            self.simgr.active = [backup.copy()]
            self.simgr.explore(find=bp, avoid=self.proj.loader.main_object.get_symbol("uart_printf_func").resolvedby.rebased_addr)
            if self.simgr.found:
                solution = self.simgr.found[0]
                self.simgr = self.proj.factory.simgr(solution)
                print(self)
            else:
                print("No solution found :(")
            import ipdb; ipdb.set_trace()

    def step(self, silent=False):
        if self.state is None:
            self.simgr.step()
            if not silent:
                print(self)
        else:
            self.inspect_simgr.step()
            if not silent:
                print(self)

    def single_step(self, silent=False):
        if self.state is None:
            self.simgr.step(num_inst=1)
            if not silent:
                print(self)
        else:
            self.inspect_simgr.step(num_inst=1)
            if not silent:
                print(self)

    def print_input_dependent_errors(self):
        errorlog = open("log/error.txt", "r")
        error = errorlog.read()
        errors = error.split("----------[ ERROR ]---------")
        interesting_errors = []
        for e in errors:
            for sym in self.symbolics:
                if sym.args[0] in e:
                    interesting_errors.append(e)
                    break
        for e in interesting_errors:
            print("----------[ ERROR ]---------\n"+e+"\n")

    def print_interesting_errors(self):
        if not os.path.exists("log/error.txt"):
            print("No errors found!")
            return
        errorlog = open("log/error.txt", "r")
        error = errorlog.read()
        errors = error.split("----------[ ERROR ]---------")[1:]
        interesting_errors = []
        for e in errors:
            if not 'uart_printf_func' in e:
                interesting_errors.append(e)
        for e in interesting_errors:
            print("----------[ ERROR ]---------\n" + e + "\n")

    def show_simple_constraints(self):
        """
        show constraints that are not too long (<200chars)
        """
        s = "Constraints:\n"
        cons = self.get_constraints()
        i = 0
        for con in cons:
            if len(str(con)) < 200:
                s += str(i) + ": " + str(con) + "\n"
            i += 1
        if len(cons) == 0:
            print("There are no constraints!")
        else:
            print(s)

    def show_interesting_constraints(self):
        """
        show all constraints that affect symbolic user input
        sorted by the affected symbolic value
        """
        symbolics = self.symbolics
        constraints = self.get_constraints()
        s = "Constraints:\n\n"
        for sym in symbolics:
            sym_name = sym.args[0]
            s += sym_name+":\n\n"
            for con in constraints:
                if sym_name in con.shallow_repr(max_depth=20):
                    s += ">> "+str(con)+"\n\n"
            s += "---------------\n"
        print(s)

    def get_constraints(self):
        return self.state.solver.constraints

    def get_state(self):
        if self.state is None:
            return self.simgr.active[0]
        return self.inspect_simgr.active[0]

    @property
    def symbolics(self):
        var_names = self.get_state().globals['state_symbolics'].split("|")
        var_list = []
        for vname in var_names:
            if vname == "":
                continue
            var_list.append(self.get_state().globals['all_symbolics'][vname])
        return var_list

    def solve_symbolics(self):
        s = "Symbolic inputs:\n"
        for sym in self.symbolics:
            sol = self.get_state().solver.eval(sym)
            sol_bytes = self.get_state().solver.eval(sym, cast_to=bytes)
            s += str(sym) + " => " + hex(sol) + " => (as bytes) " + str(sol_bytes) + "\n"
        print(s)

    def check_block_for_taints(self, start_addr=0x0, end_addr=None):
        if end_addr is None:
            end_addr = start_addr
        if not self.explore(find=start_addr, silent=True):
            return [["The provided Block could not be reached! :("], ["No taints found."]]
        annos = []
        used_annos = []
        current_addr = hex(start_addr-4)
        while True:
            ans = self.list_annotations(silent=True)
            # print("Check at address:", current_addr)
            for a in ans:
                """
                check registers and referenced memory for occurrence of tainted values
                """
                if not any(a[1] in tmp for tmp in annos):
                    new_entry = [current_addr, self.get_state().globals['call_count']]
                    new_entry.extend(a)
                    if current_addr == hex(start_addr - 4):
                        # note whether value was stored before reaching the new block or if it appeared within the new block
                        new_entry.append("before block")
                    else:
                        new_entry.append("in block")
                    annos.append(new_entry)
                    # print("new user-input:", a, "found at", current_addr)

            if int(current_addr, 16) >= start_addr:
                """
                check current line of assembly code for usage of tainted values
                """
                bb = self.proj.factory.block(self.base_address+int(current_addr, 16), size=4)
                for a in annos:
                    check_reg = a[2].split(" -> ")[0]
                    if check_reg in str(bb.capstone):
                        # tainted value seems to be used in code; check the results carefully, as there might be some false positives!
                        new_entry = [current_addr, check_reg, str(bb.capstone).replace("\t", "  ")]
                        if not new_entry in used_annos:
                            used_annos.append(new_entry)
                # print(bb.capstone)

            if int(current_addr, 16) == end_addr:
                break
            current_addr = hex(self.get_state().addr-self.base_address)
            self.single_step(silent=True)
        """for a in annos:
            print(a)"""
        return annos, used_annos

    def list_annotations(self, silent=False):
        from securestoragehooks import UserInput
        sources = []
        for r in range(15):
            reg_name = "r" + str(r)
            reg = self.get_state().registers.load(reg_name)
            for a in reg._relocatable_annotations:
                if not silent:
                    print("------------------------------")
                    print("Register:", reg_name, "=>", reg)
                    print("Annotation:", a)
                    print("UserInput:", type(a) == UserInput)
                    print("Source:", a.SOURCE)
                """if not any(a.SOURCE in s for s in sources):
                    sources.append([reg_name, a.SOURCE])"""
                if not [reg_name, a.SOURCE] in sources:
                    sources.append([reg_name, a.SOURCE])
            if not reg.symbolic:
                reg_addr = self.get_state().solver.eval(reg)
                reg_byte = self.get_state().mem[reg_addr].byte.resolved
                for a in reg_byte._relocatable_annotations:
                    if not silent:
                        print("------------------------------")
                        print("Address:", hex(reg_addr), "=>", reg_byte)
                        print("Referenced from register:", reg_name)
                        print("Annotation:", a)
                        print("UserInput:", type(a) == UserInput)
                        print("Source:", a.SOURCE)
                    """if not any(a.SOURCE in s for s in sources):
                        sources.append([reg_name, a.SOURCE])"""
                    if not [hex(reg_addr), a.SOURCE] in sources:
                        sources.append([reg_name+" -> "+hex(reg_addr), a.SOURCE])

        # print(sources)
        return sources

    def explore(self, find=None, avoid=None, silent=False):
        if not avoid is None:
            avoid = int(avoid) + self.base_address
        else:
            """
            avoid the 'uart_printf_func'-function, as this implies an error
            and therefore shouldn't be, what we are looking for
            """
            avoid = self.proj.loader.main_object.get_symbol("uart_printf_func").resolvedby.rebased_addr
        # select the correct simulation manager for exploration
        if self.state is None:
            simgr = self.simgr
        else:
            simgr = self.inspect_simgr
        simgr.explore(find=self.base_address+int(find), avoid=avoid, num_find=1)
        if simgr.found:
            # inspect/compare simgr.found[0/1] here to see two solutions for opensession
            solution = simgr.found[0]
            simgr = self.proj.factory.simgr(solution)
            # write the result back to the correct simulation manager
            if self.state is None:
                self.simgr = simgr
            else:
                self.inspect_simgr = simgr
            if not silent:
                print(self)
            return True
        else:
            print("Couldn't find a solution :(")
            return False

    def xfp(self, off=0x0, nelem=1):
        """ gdb's x/[nelem]wd fp+off on simgr's first active state. """
        if len(self.simgr.active) > 0:
            state = self.simgr.active[0]
            out = ""
            for i in range(nelem):
                out += "{:<8}: {}\n".format("fp+{:#x}".format(off + i * 4),
                                            state.mem[state.solver.eval(state.regs.r11) + off + i * 4].int)
            return out
        else:
            return "No active states."

    def init_state(self, state):

        # init heap memory
        for addr in range(self.heap_base, self.heap_base + self.heap_size, 8):
            state.memory.store(addr, state.solver.BVV(struct.unpack("<Q", b"A" * 8)[0], 64))

        state.globals['heap_base'] = self.heap_base
        state.globals['heap_size'] = self.heap_size
        state.globals['malloc_off'] = 0x0

        # init stack memory
        for addr in range(self.stack_base, self.stack_base + self.stack_size, 8):
            state.memory.store(addr, state.solver.BVV(struct.unpack("<Q", b"B" * 8)[0], 64))

        # init shared memory
        for addr in range(self.shared_mem_base, self.shared_mem_base + self.shared_mem_sz, 8):
            state.memory.store(addr, state.solver.BVV(struct.unpack("<Q", b"C" * 8)[0], 64))

        # set registers
        state.regs.r0 = claripy.BVV(0x0, 32)
        state.regs.r1 = claripy.BVV(0x0, 32)
        state.regs.r2 = claripy.BVV(0x0, 32)
        state.regs.r3 = claripy.BVV(0x0, 32)

        state.regs.r4 = claripy.BVV(0x0, 32)
        state.regs.r5 = claripy.BVV(0x0, 32)
        state.regs.r6 = claripy.BVV(0x0, 32)
        state.regs.r7 = claripy.BVV(0x0, 32)
        state.regs.r8 = claripy.BVV(0x0, 32)
        state.regs.r9 = claripy.BVV(0x0, 32)
        state.regs.r10 = claripy.BVV(0x0, 32)

        # TODO: calculate fp and sp from classmember variables
        # frame pointer
        state.regs.r11 = claripy.BVV(0x11bb000, 32)

        # scratch register/new -sb in inter-link-unit calls
        state.regs.r12 = claripy.BVV(0x0, 32)

        # stack pointer: stack frame is ~0xe4 so we give 0xf0 initially
        state.regs.r13 = claripy.BVV(0x11bb000 - 0xf0, 32)

        # link register
        state.regs.r14 = claripy.BVV(0x0, 32)

        # init stack frame of tee_task_entry assuming we begin execution @0x14C8
        state.regs.r8 = state.regs.r11 - claripy.BVV(0xb0, 32)  # lifecycle_cmd_id
        state.regs.r9 = state.regs.r11 - claripy.BVV(0x9c, 32)  # lifecycle_context_struct
        state.regs.r10 = state.regs.r11 - claripy.BVV(0x8c, 32)

        # fake memory
        # one byte "ta_needs_init", we do not want an init
        # having this set, we are skipping TA_CreateEntryPoint()
        state.mem[state.regs.r11 - claripy.BVV(0x70, 32)].int = claripy.BVV(0x0, 32)
        return

    def install_hooks(self, proj):
        """ installs all Hook.* classes from securestoragehooks module. """
        import inspect
        import securestoragehooks
        clazzes = [m for m in inspect.getmembers(securestoragehooks, inspect.isclass)
                   if m[1].__module__ == securestoragehooks.__name__]

        for clazz_name, clazz in clazzes:
            if not clazz_name.startswith("Hook"):
                continue
            syms = proj.loader.find_all_symbols(clazz.SYMBOL)
            current_clazz = clazz()
            for sym in syms:
                if proj.is_hooked(sym.rebased_addr):
                    proj.unhook(sym.rebased_addr)
                proj.hook_symbol(sym.rebased_addr, current_clazz)

        return


def setup_args():
    """ setup command line argument parsing and return argparse parser object. """
    parser = argparse.ArgumentParser()

    def auto_int(x):
        """ for auto base detection during arg parsing. """
        return int(x, 0)

    sub_parsers = parser.add_subparsers(title='Mode', dest='mode',
                                        help='Mode of operation.')

    exec_group = sub_parsers.add_parser("exec")

    # setup exec group parser
    exec_group.add_argument("ta_binary",
                            help="TrustedCore trusted application ELF to be executed.")
    exec_group.add_argument("lifecycle_entry", type=auto_int,
                            help="Lifecycle entry address from ta_binary.")
    exec_group.add_argument("tee_lib",
                            help="TrustedCore tee lib ELF used by ta_binary (e.g., globaltask).")
    exec_group.add_argument("call_sequence_module",
                            help="Python module providing the user input.")
    exec_group.add_argument("breakpoints", metavar='N', type=auto_int, nargs='*',
                            help="Set breakpoint addresses. "
                                 "Note that we can only break at basic block entries for now.")

    exec_group = sub_parsers.add_parser("filter")
    exec_group.add_argument("ta_binary",
                            help="(Patched) TrustedCore trusted application ELF to be executed.")
    exec_group.add_argument("lifecycle_entry", type=auto_int,
                            help="Lifecycle entry address from ta_binary.")
    exec_group.add_argument("tee_lib",
                            help="TrustedCore tee lib ELF used by ta_binary (e.g., globaltask).")
    exec_group.add_argument("call_sequence_module",
                            help="Python module providing the user input.")
    exec_group.add_argument("basic_blocks", metavar='N', type=auto_int, nargs='*',
                            help="Set basic_block start and end addresses. ")

    sub_parsers.add_parser("diff")

    return parser


def main():
    arg_parser = setup_args()
    args = arg_parser.parse_args()

    if args.mode == "exec":
        secstor = SimTA(args.ta_binary, args.lifecycle_entry, args.tee_lib,
                        args.call_sequence_module, args.breakpoints)
        secstor.run()

    elif args.mode == "filter":
        result = ""
        for bb in range(len(args.basic_blocks))[::2]:
            secstor = SimTA(args.ta_binary, args.lifecycle_entry, args.tee_lib,
                            args.call_sequence_module, [])
            start = args.basic_blocks[bb]
            end = args.basic_blocks[bb+1]
            taints = secstor.check_block_for_taints(start, end)

            result += "Tainted values that appear in block from " + hex(start) + " to " + hex(end) + ":\n"
            for taint in taints[0]:
                result += "\t" + str(taint) + "\n"

            result += "Tainted values that are used in this block:\n"
            for taint in taints[1]:
                result += "\t" + str(taint) + "\n"
            result += "\n"

        result += "\n"
        print(result)
        import ipdb;ipdb.set_trace()

    elif args.mode == "diff":
        raise NotImplementedError("Implement me!")
        secstor = SimTA(args.ta_binary, args.lifecycle_entry, args.tee_lib)
        secstor.run_explore()
        secstor.explore(0x570)
    else:
        arg_parser.print_help()


if __name__ == "__main__":
    main()
