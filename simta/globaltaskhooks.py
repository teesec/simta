import angr, claripy




class HookGlobaltask(angr.SimProcedure):
    NO_RET = True
    IS_FUNCTION = True
    local_vars = ('lr',)

    def run(self):
        # print("Hookin some globaltask")
        # safe the original LinkRegister to return after stub
        self.lr = self.state.regs.r14.ast.args[0]
        sym_name = self.state.project.loader.find_symbol(self.state.addr).name
        sym_addr = self.state.project.loader.all_objects[0].get_symbol(sym_name).rebased_addr
        # print("Sym_name:",sym_name,"\nSym_addr:",hex(sym_addr))
        self.call(sym_addr, args=(), continue_at="done")

    def done(self):
        # print(self.state)
        self.jump(self.lr)


class HookCheckObject(angr.SimProcedure):
    SYMBOL = "check_object"
    IS_FUNCTION = True

    def run(self):
        self.state.regs.r0 = self.state.mem[self.state.solver.eval(self.state.regs.r11) - 0x10].int.resolved
        sym=self.project.loader.find_symbol(self.SYMBOL)
        self.call(sym.rebased_addr,args=(),continue_at="done")

    def done(self):
        pass


class HookAddObject(angr.SimProcedure):
    SYMBOL = "add_object"
    IS_FUNCTION = True

    def run(self):
        self.state.regs.r0 = self.state.mem[self.state.solver.eval(self.state.regs.r11) - 0x10].int.resolved
        sym=self.project.loader.find_symbol(self.SYMBOL)
        self.call(sym.rebased_addr,args=(),continue_at="done")

    def done(self):
        pass


class HookAddList(angr.SimProcedure):
    SYMBOL = "add_list"
    IS_FUNCTION = True

    def run(self):
        self.state.regs.r0 = self.state.mem[self.state.solver.eval(self.state.regs.r11) - 0x10].int.resolved
        self.call(self.project.loader.find_symbol(self.SYMBOL).rebased_addr, args=(), continue_at="done")

    def done(self):
        pass
