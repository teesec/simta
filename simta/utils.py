import colorama

colorama.init(autoreset=True)


def get_stack(state):
    out = "----------["
    out += colorama.Fore.MAGENTA + " stack " + colorama.Fore.WHITE + colorama.Style.RESET_ALL
    out += "]---------\n"

    sp = state.solver.eval(state.regs.r13)
    for idx in range(0x10):
        out += "{:<16}{}\n".format("{:#x}:".format(sp+idx*4), state.mem[sp+idx*4].int)
    return out


def get_bb(proj, state):
    out = "----------["
    out += colorama.Fore.RED + " disasm " + colorama.Fore.WHITE + colorama.Style.RESET_ALL
    out += "]---------\n"

    pc = state.solver.eval(state.regs.r15)
    bb = proj.factory.block(pc)

    out += "{}\n".format(bb.capstone)
    return out


def get_regs(state):
    out = "----------["
    out += colorama.Fore.BLUE + " registers " + colorama.Fore.WHITE + colorama.Style.RESET_ALL
    out += "]---------\n"
    try:
        out += state.project.loader.find_symbol(state.regs.r15.args[0]).name+"\n"
    except:
        pass
    out += "{:<8}: {}\n".format("r0", state.regs.r0)
    out += "{:<8}: {}\n".format("r1", state.regs.r1)
    out += "{:<8}: {}\n".format("r2", state.regs.r2)
    out += "{:<8}: {}\n".format("r3", state.regs.r3)
    out += "{:<8}: {}\n".format("r4", state.regs.r4)
    out += "{:<8}: {}\n".format("r5", state.regs.r5)
    out += "{:<8}: {}\n".format("r6", state.regs.r6)
    out += "{:<8}: {}\n".format("r7", state.regs.r7)
    out += "{:<8}: {}\n".format("r8", state.regs.r8)
    out += "{:<8}: {}\n".format("r9 (SB)", state.regs.r9)
    out += "{:<8}: {}\n".format("r10 (SL)", state.regs.r10)
    out += "{:<8}: {} --> {}\n".format("r11 (FP)", state.regs.r11, state.mem[state.solver.eval(state.regs.r11)].int)
    out += "{:<8}: {}\n".format("r12 (IP)", state.regs.r12)
    out += "{:<8}: {} --> {}\n".format("r13 (SP)", state.regs.r13, state.mem[state.solver.eval(state.regs.r13)].int)
    out += "{:<8}: {}\n".format("r14 (LR)", state.regs.r14)
    out += "{:<8}: {}\n".format("r15 (PC)", state.regs.r15)
    return out


def get_context(proj, state):
    out = get_regs(state)
    out += get_bb(proj, state)
    out += get_stack(state)
    return out


def print_state(proj, state):
    out = get_regs(state)
    out += get_bb(proj, state)
    out += get_stack(state)
    print(out)


def print_vex(proj, state):
    """
    :param state:
    print the lifted VEX-Code of the given state
    """
    print("----------------DUMP VEX-CODE----------------")
    sym = proj.loader.find_symbol(state.addr)
    print("Symbol:", sym,"\nAddress:",hex(state.addr))
    vex = proj.factory.block(state.addr).vex
    vex.pp()


def print_disasm(proj, state):
    """
    :param state:
    print basic block of the given state
    """
    print("----------------DUMP ASM-CODE----------------")
    sym = proj.loader.find_symbol(state.addr)
    print("Symbol:", sym,"\nAddress:",hex(state.addr))
    proj.factory.block(state.addr).pp()
