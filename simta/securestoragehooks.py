import hashlib
import angr, claripy
import colorama
import os
from simta.simta import SimTA


""" Constants """
MAX_STRLEN = 256

TEE_STORAGE_PRIVATE = 0x1


class LifecycleCommandIds:
    OPEN_SESSION = 0x11
    INVOKE_COMMAND = 0x12
    CLOSE_SESSION = 0x13


class InvokeCommandIds:
    FOPEN = 0x11
    FREAD = 0x14
    FSEEK = 0x16
    FWRITE = 0x15
    FCLOSE = 0x12


class OperationAlgorithms:
    TEE_ALG_SHA256 = 0x50000004


class OperationModes:
    TEE_MODE_ENCRYPT = 0
    TEE_MODE_DECRYPT = 1
    TEE_MODE_SIGN = 2
    TEE_MODE_VERIFY = 3
    TEE_MODE_MAC = 4
    TEE_MODE_DIGEST = 5
    TEE_MODE_DERIVE = 6


class ReturnTypes:
    TEE_SUCCESS = 0x0
    TEE_ERROR_ITEM_NOT_FOUND = 0xFFFF0008
    TEE_ERROR_SHORT_BUFFER = 0xFFFF0010


class DataFlags:
    TEE_DATA_FLAG_ACCESS_READ = 0x1
    TEE_DATA_FLAG_ACCESS_WRITE = 0x2
    TEE_DATA_FLAG_ACCESS_WRITE_META = 0x4
    TEE_DATA_FLAG_SHARE_READ = 0x10
    TEE_DATA_FLAG_SHARE_WRITE = 0x20
    TEE_DATA_FLAG_CREATE = 0x200
    TEE_DATA_FLAG_EXCLUSIVE = 0x400


class TeeWhence:
    TEE_DATA_SEEK_SET = 0x0
    TEE_DATA_SEEK_CUR = 0x1
    TEE_DATA_SEEK_END = 0x2


"""User-Input-Annotation"""


class UserInput(claripy.Annotation):
    SOURCE = None

    def __init__(self, src=None):
        self.SOURCE = src

    @property
    def eliminatable(self):
        return False
    @property
    def relocatable(self):
        return True


""" Helper """


def get_string(state, pos):
    s = ""
    i = 0
    while 1:
        b = state.mem[pos + i].byte.resolved.args[0]
        if type(b) != int or b == 0:
            break
        s += chr(b)
        i += 1
    return s


def get_bytestring(state, addr, strlen):
    s = b""
    for i in range(state.solver.eval(strlen)):
        c = state.mem[addr+i].byte.concrete
        s += bytes([c])
    return s


def organize_symbolic_strings(state, str1, str2):
    """
    get two pointer to strings and decide, which one is symbolic and which one is concrete
    :return the symbolic string, the concrete string, the length of the concrete string, and a bool (True, if one string is symbolic)
    """
    str1_start = state.mem[str1].byte.resolved
    str2_start = state.mem[str2].byte.resolved
    sym_str = None  # symbolic string to work with
    con_str = None  # concrete string to compare with
    if str1_start.symbolic and str2_start.symbolic:
        print("ERROR: Try to compare two symbolic strings...")
        return [None, None, None, True]
    elif str1_start.symbolic:
        s = get_string(state, str2)
        n = len(s)
        sym_str = str1
        con_str = str2
    elif str2_start.symbolic:
        s = get_string(state, str1)
        n = len(s)
        sym_str = str2
        con_str = str1
    else:
        return [str1, str2, len(get_string(state, str1)), False]
    return [sym_str, con_str, n, True]


def extract_operation_handle(state, operation_handle_id):
    op = 'op_'+str(operation_handle_id)
    op_handle = state.globals[op]
    contents = op_handle.split("|")
    algorithm = int(contents[0], 16)
    mode = int(contents[1], 16)
    maxKeySize = int(contents[2], 16)
    handle_id = contents[3]     # key for globals-dict, where bytes to be hashed are stored
    return algorithm, mode, maxKeySize, handle_id


def get_object_id(state, object_handle):
    # get object_id from object_handle
    object_id_len = state.mem[object_handle + 0x4].int.resolved
    return state.solver.eval(state.memory.load(object_handle + 0x8, object_id_len), cast_to=bytes)


def get_data_position(state, object_handle):
    # get data_position from object_info of object_handle
    object_info_pointer = state.solver.eval(state.mem[object_handle + 0x108].int.resolved)
    return state.solver.eval(state.mem[object_info_pointer + 0x14].int.resolved)


def set_data_position(state, object_handle, value):
    # set data_position of object_handle in object_info
    object_info_pointer = state.solver.eval(state.mem[object_handle + 0x108].int.resolved)
    state.mem[object_info_pointer + 0x14].int = value


def get_data_size(state, object_handle):
    # get data_size from object_info of object_handle
    object_info_pointer = state.solver.eval(state.mem[object_handle + 0x108].int.resolved)
    return state.solver.eval(state.mem[object_info_pointer + 0x10].int.resolved)


def set_data_size(state, object_handle, value):
    # set data_size of object_handle in object_info
    object_info_pointer = state.solver.eval(state.mem[object_handle + 0x108].int.resolved)
    state.mem[object_info_pointer + 0x10].int = value


def get_object_handle_flags(state, object_handle):
    # get flags from object_info in object_handle
    object_info_pointer = state.solver.eval(state.mem[object_handle + 0x108].int.resolved)
    flags = state.solver.eval(state.mem[object_info_pointer + 0x18].int.resolved)
    return flags


def print_error(error):
    out = "\n----------[ ERROR ]---------\n" + error
    print(colorama.Fore.RED + out + "\n----------[ ERROR ]---------\n" + colorama.Fore.WHITE + colorama.Style.RESET_ALL)
    if not os.path.isdir(SimTA.LOGDIR):
        os.mkdir(SimTA.LOGDIR)
    errorlog = open(os.path.join(SimTA.LOGDIR, SimTA.ERRORLOG), "a")
    errorlog.write(out)
    errorlog.close()


""" Hooks """


class HookStrncat(angr.SIM_PROCEDURES['libc']['strcat']):
    SYMBOL = "strncat"
    # hook strncat with strcat, because it should work in our case


class HookTeeMemMove(angr.SimProcedure):
    SYMBOL = "TEE_MemMove"

    def run(self):
        result = self.state.solver.eval(self.state.regs.r0)
        src = self.state.solver.eval(self.state.regs.r1)
        n = self.state.solver.max(self.state.regs.r2)   # if we get a symbolic n, we copy as many bytes as possible

        # check inputs for symbolic values; stop execution branch if relevant inputs are symbolic
        sym_in = []
        if self.state.regs.r0.symbolic:
            sym_in.append("Destination: "+str(self.state.regs.r0))
        if self.state.regs.r1.symbolic:
            sym_in.append("Source: "+str(self.state.regs.r1))
        if self.state.regs.r2.symbolic:
            # if only size is symbolic, we copy as many bytes as possible, otherwise, we add size to the error message
            # give some fixed upper bound for MemMove size to avoid endless loops in case of bad inputs
            if len(sym_in) > 0 or n > 2*MAX_STRLEN:
                sym_in.append("Size: "+str(self.state.regs.r2))
        if len(sym_in) > 0:
            error = "MemMove got the following symbolic inputs: " + str(sym_in) + "\n" + str(self.state.callstack)
            self.returns = False
            print_error(error)
            return

        for i in range(n):
            self.state.mem[result + i].byte = self.state.mem[src + i].byte.resolved


class HookTEEMemCompare(angr.SimProcedure):
    SYMBOL = "TEE_MemCompare"

    def run(self):
        # check inputs for symbolic values; stop execution branch if relevant inputs are symbolic
        sym_in = []
        if self.state.regs.r0.symbolic:
            sym_in.append("s1_addr: " + str(self.state.regs.r0))
        if self.state.regs.r1.symbolic:
            sym_in.append("s2_addr: " + str(self.state.regs.r1))
        if self.state.regs.r2.symbolic:
            # if only size is symbolic, we copy as many bytes as possible, otherwise, we add size to the error message
            # give some fixed upper bound for MemMove size to avoid endless loops in case of bad inputs
            if len(sym_in) > 0 or self.state.solver.max(self.state.regs.r2) > 2 * MAX_STRLEN:
                sym_in.append("Size: " + str(self.state.regs.r2))
        if len(sym_in) > 0:
            error = "MemCompare got the following symbolic inputs: " + str(sym_in) + "\n" + str(self.state.callstack)
            self.returns = False
            print_error(error)
            return

        res = self.inline_call(angr.SIM_PROCEDURES['libc']['memcmp'], self.state.regs.r0, self.state.regs.r1, self.state.regs.r2)
        self.state.regs.r0 = res.ret_expr



class HookStrlen(angr.SIM_PROCEDURES['libc']['strlen']):
    SYMBOL = "strlen"


class HookUartPrintfFunc(angr.SimProcedure):
    SYMBOL = "uart_printf_func"

    def run(self):
        error = "Reached 'uart_printf_func' which indicates an error!\n"+str(self.state.callstack)
        self.returns = False
        print_error(error)
        # import ipdb;
        # ipdb.set_trace()


class HookMemset(angr.SIM_PROCEDURES['libc']['memset']):
    SYMBOL = "memset"


class HookSetCurrentSessionType(angr.SimProcedure):
    SYMBOL = "set_current_session_type"

    def run(self):
        """ this function does nothing. """
        return


class HookGetCurrentSessionId(angr.SimProcedure):
    SYMBOL = "get_current_session_id"

    def run(self):
        """ this function does nothing. """
        return 420


class HookTeeSessionInit(angr.SimProcedure):
    SYMBOL = "tee_session_init"

    def run(self):
        """ this function calls globaltask's add_session_cancel_state() internally, we might need this later. """
        return


class HookTeeInitContext(angr.SimProcedure):
    SYMBOL = "tee_init_context"

    def run(self):
        """ this function sets two global variables, we might implement this later. """
        return


class InputCallSequenceException(Exception):
    pass


class NoPermissionException(Exception):
    pass


class SymbolicInputException(Exception):
    pass


class HookSreMsgRcv(angr.SimProcedure):
    SYMBOL = "__SRE_MsgRcv"

    def __init__(self):
        super(HookSreMsgRcv, self).__init__()
        self.lifecycle = None

    def run(self):

        if not self.lifecycle:
            # init the call sequence list if it's not initialized yet
            if "call_sequence_module" not in self.state.globals:
                raise InputCallSequenceException("Input call sequence module is missing.")
            modules = self.state.globals["call_sequence_module"].split(".")
            mod = __import__(".".join(modules[:-1]), fromlist=[''])
            lifecycle_cls = getattr(mod, modules[-1])
            self.lifecycle = lifecycle_cls()

        # reset sym_rets after each cycle
        self.state.globals['sym_rets'] = []

        # keep track of Lifecycle (call_count)
        if 'call_count' in self.state.globals:
            self.state.globals['call_count'] += 1
            cc = self.state.globals['call_count']
        else:
            cc = 0
            self.state.globals['call_count'] = cc

        if 0 <= cc < len(self.lifecycle):
            self.lifecycle[cc](self.state)
        else:
            raise InputCallSequenceException("No calls in input sequence (cc = {} vs len(sequence) = {}."
                                             .format(cc, len(self.lifecycle)))

        return


class HookSreMsgSnd(angr.SimProcedure):
    SYMBOL = "__SRE_MsgSnd"

    def run(self):
        lifecycle_cmd_id = self.state.regs.r0
        global_handle = self.state.regs.r1
        framework_ctx = self.state.regs.r2
        sz = self.state.regs.r3  # 16

        if 'lifecycle_cmd_id' in self.state.globals and 'invoke_cmd_id' in self.state.globals:
            if self.state.solver.is_true(self.state.globals['lifecycle_cmd_id'] == LifecycleCommandIds.INVOKE_COMMAND) and \
                    self.state.solver.is_true(self.state.globals['invoke_cmd_id'] == InvokeCommandIds.FOPEN):
                object_handle = self.state.mem[self.state.regs.r5].TC_NS_Parameter.struct.memref.array(4)[2].buffer.resolved
                self.state.globals['current_object_handle_ptr'] = object_handle

        if self.state.solver.is_true(lifecycle_cmd_id == LifecycleCommandIds.OPEN_SESSION) and 'sessionContext' not in self.state.globals:
            self.state.globals['sessionContext'] = self.state.mem[framework_ctx + 0x8].int.resolved


class HookTeeMalloc(angr.SimProcedure):
    SYMBOL = "TEE_Malloc"

    def run(self):
        """hex(object_pointer)
        looking for 'size' free (=0) bytes in a row
        (should work)
        """
        # TODO: implement original heap
        size = self.state.regs.r0.ast
        keep_Data = self.state.regs.r1.ast

        if not type(size.args[0]) == int:  # if input is symbolic, return fixed size of memory
            size = claripy.BVV(0x200, 32)

        heap_base = self.state.globals.get('heap_base')
        heap_size = self.state.globals.get('heap_size')
        off = self.state.globals.get('malloc_off')  # we keep track of the offset of allocated chunks

        self.state.regs.r0 = heap_base + off  # return start_address where memory can be accessed
        self.state.globals['malloc_off'] = off + size.args[0] + 0x10

        if heap_base + self.state.globals['malloc_off'] > heap_base + heap_size:
            raise NotImplementedError("Come up with a better heap implementation!")

        """if not keep_Data.args[0]:
            self.state.regs.r1 = b"\x00"
            self.state.regs.r2 = size
            self.inline_call(hook_tee_memfill)"""


class HookTeeFree(angr.SimProcedure):
    SYMBOL = "TEE_Free"

    def run(self):
        # TODO: implement correct heap
        return
        addr = self.state.regs.r0.ast
        i = 0
        while 1:
            b = self.state.mem[addr + i].byte
            if b.concrete:
                self.state.memory.store(addr + i, b"\x00")
                i += 1
            else:
                break


class HookTeeMemFill(angr.SIM_PROCEDURES['libc']['memset']):
    SYMBOL = "TEE_MemFill"


class HookStrstr(angr.SimProcedure):
    SYMBOL = "strstr"

    def run(self):
        # check inputs for symbolic values; stop execution branch if relevant inputs are symbolic
        sym_in = []
        if self.state.regs.r0.symbolic:
            sym_in.append("haystack: " + str(self.state.regs.r0))
        if self.state.regs.r1.symbolic:
            sym_in.append("needle: " + str(self.state.regs.r1))
        if len(sym_in) > 0:
            error = "strstr got the following symbolic inputs: " + str(sym_in) + "\n" + str(self.state.callstack)
            self.returns = False
            print_error(error)
            return

        res = self.inline_call(angr.SIM_PROCEDURES['libc']['strstr'], self.state.regs.r0, self.state.regs.r1)
        self.state.regs.r0 = res.ret_expr


class HookMemcpy(angr.SimProcedure):
    SYMBOL = "memcpy"

    def run(self):
        # check inputs for symbolic values; stop execution branch if relevant inputs are symbolic
        sym_in = []
        if self.state.regs.r0.symbolic:
            sym_in.append("Destination: " + str(self.state.regs.r0))
        if self.state.regs.r1.symbolic:
            sym_in.append("Source: " + str(self.state.regs.r1))
        if self.state.regs.r2.symbolic:
            # if only size is symbolic, we copy as many bytes as possible, otherwise, we add size to the error message
            # give some fixed upper bound for MemMove size to avoid endless loops in case of bad inputs
            if len(sym_in) > 0 or self.state.solver.max(self.state.regs.r2) > 2 * MAX_STRLEN:
                sym_in.append("Size: " + str(self.state.regs.r2))
        if len(sym_in) > 0:
            error = "Memcpy got the following symbolic inputs: " + str(sym_in) + "\n" + str(self.state.callstack)
            self.returns = False
            print_error(error)
            return

        res = self.inline_call(angr.SIM_PROCEDURES['libc']['memcpy'], self.state.regs.r0, self.state.regs.r1, self.state.regs.r2)
        self.state.regs.r0 = res.ret_expr

"""
GP Internal Core API functions
"""


class HookTeeCreatePersistentObject(angr.SimProcedure):
    SYMBOL = "TEE_CreatePersistentObject"

    # TODO: if really necessary, some restrictions have to be checked (e.g. objectID must not point to shared memory)
    #  look at GP Internal Core API for further information

    def run(self):
        storage_id = self.state.solver.eval(self.state.regs.r0)
        object_id_pointer = self.state.solver.eval(self.state.regs.r1)
        object_id_len = self.state.solver.eval(self.state.regs.r2)
        flags = self.state.solver.eval(self.state.regs.r3)
        attributes = self.state.solver.eval(self.state.mem[self.state.regs.r13].int.resolved)
        initial_data_pointer = self.state.solver.eval(self.state.mem[self.state.regs.r13+0x4].int.resolved)
        initial_data_len = self.state.solver.eval(self.state.mem[self.state.regs.r13+0x8].int.resolved)
        object_pointer = self.state.solver.eval(self.state.mem[self.state.regs.r13+0xc].int.resolved)

        if storage_id != TEE_STORAGE_PRIVATE:
            return ReturnTypes.TEE_ERROR_ITEM_NOT_FOUND

        # chack inputs for symbolic values
        sym_in = []
        if self.state.regs.r1.symbolic:
            sym_in.append("object_id: " + str(self.state.regs.r1))
        if self.state.regs.r2.symbolic:
            sym_in.append("object_id_len: " + str(self.state.regs.r2))
        if self.state.regs.r3.symbolic:
            sym_in.append("flags: " + str(self.state.regs.r3))
        if self.state.mem[self.state.regs.r13].int.resolved.symbolic:
            sym_in.append("attributes: " + str(self.state.mem[self.state.regs.r13].int.resolved))
        if self.state.mem[self.state.regs.r13+0x4].int.resolved.symbolic:
            sym_in.append("initial_data_pointer: " + str(self.state.mem[self.state.regs.r13+0x4].int.resolved))
        if self.state.mem[self.state.regs.r13+0x8].int.resolved.symbolic:
            sym_in.append("initial_data_len: " + str(self.state.mem[self.state.regs.r13+0x8].int.resolved))
        if self.state.mem[self.state.regs.r13 + 0xc].int.resolved.symbolic:
            sym_in.append("object_handle_pointer: " + str(self.state.mem[self.state.regs.r13 + 0xc].int.resolved))
        if len(sym_in) > 0:
            error = "CreatePersistentObject got the following symbolic inputs: " + str(sym_in) + "\n" + str(self.state.callstack)
            self.returns = False
            print_error(error)
            return

        # Allocate memory for object_handle (0x11c)
        self.state.regs.r0 = 0x11c
        self.state.regs.r1 = 0x0
        self.inline_call(HookTeeMalloc)
        object_handle_memory = self.state.solver.eval(self.state.regs.r0)
        self.state.memory.store(object_handle_memory, b"E"*0x11c)

        # write address of object_handle to outbuf
        self.state.mem[object_pointer].int = object_handle_memory

        # Allocate memory for object_info (0x1c)
        self.state.regs.r0 = 0x1c
        self.state.regs.r1 = 0x0
        self.inline_call(HookTeeMalloc)
        object_info_memory = self.state.solver.eval(self.state.regs.r0)
        self.state.memory.store(object_info_memory, b"F" * 0x1c)

        # write address of object_info to object_handle
        self.state.mem[object_handle_memory + 0x108].int = object_info_memory

        # object_handle starts with pointer to itself, followed by objectIDLen
        self.state.mem[object_handle_memory].int = object_handle_memory
        self.state.mem[object_handle_memory + 0x4].int = object_id_len

        # write objectID to object_handle (followed by nullbyte)
        self.state.regs.r0 = object_handle_memory + 0x8
        self.state.regs.r1 = object_id_pointer
        self.state.regs.r2 = object_id_len
        self.inline_call(HookTeeMemMove)
        self.state.mem[object_handle_memory + object_id_len + 0x8].byte = 0x0

        # TODO: is this just one current_data_position counter for read and write or two seperate counters?
        # write value to represent the current data_read_position
        self.state.mem[object_handle_memory + object_id_len + 0xc].int = 0x0

        # write value to represent the current data_write_position
        self.state.mem[object_handle_memory + object_id_len + 0x10].int = 0x0

        # write object_info data
        self.state.mem[object_info_memory].int = 0xA1000033             # object_type
        self.state.mem[object_info_memory + 0x4].int = 0x0              # object_size
        self.state.mem[object_info_memory + 0x8].int = 0xFFFFFFFF       # max_object_size
        self.state.mem[object_info_memory + 0xc].int = 0xFFFFFFFF       # object_usage
        self.state.mem[object_info_memory + 0x10].int = 0x0             # data_size
        self.state.mem[object_info_memory + 0x14].int = 0x0             # data_position
        self.state.mem[object_info_memory + 0x18].int = flags | 0x30000  # handle_flags

        # Allocate memory for object_info_append (0xc)
        self.state.regs.r0 = 0xc
        self.state.regs.r1 = 0x0
        self.inline_call(HookTeeMalloc)
        object_info_append_memory = self.state.solver.eval(self.state.regs.r0)
        self.state.memory.store(object_info_append_memory, b"G" * 0xc)

        # write address of object_info_append to object_handle
        self.state.mem[object_handle_memory + 0x118].int = object_info_append_memory

        # create 'file-object' in globals-dict
        object_id = self.state.solver.eval(self.state.mem[object_id_pointer].string.resolved, cast_to=bytes)
        self.state.globals[object_id] = b''

        return ReturnTypes.TEE_SUCCESS


class HookTeeOpenPersistentObject(angr.SimProcedure):
    SYMBOL = "TEE_OpenPersistentObject"

    # TODO: if really necessary, some restrictions have to be checked (e.g. objectID must not point to shared memory)
    #  look at GP Internal Core API for further information

    def run(self):
        storage_id = self.state.solver.eval(self.state.regs.r0)
        object_id_pointer = self.state.solver.eval(self.state.regs.r1)
        object_id_len = self.state.solver.eval(self.state.regs.r2)
        flags = self.state.solver.eval(self.state.regs.r3)
        object_pointer = self.state.solver.eval(self.state.mem[self.state.regs.r13].int.resolved)

        # bad storage_id
        if storage_id != TEE_STORAGE_PRIVATE:
            return ReturnTypes.TEE_ERROR_ITEM_NOT_FOUND

        # check inputs for symbolic values
        sym_in = []
        if self.state.regs.r1.symbolic:
            sym_in.append("object_id: " + str(self.state.regs.r1))
        if self.state.regs.r2.symbolic:
            sym_in.append("object_id_len: " + str(self.state.regs.r2))
        if self.state.regs.r3.symbolic:
            sym_in.append("flags: " + str(self.state.regs.r3))
        if self.state.mem[self.state.regs.r13].int.resolved.symbolic:
            sym_in.append("object_handle_pointer: " + str(self.state.mem[self.state.regs.r13].int.resolved))
        if len(sym_in) > 0:
            error = "OpenPersistentObject got the following symbolic inputs: " + str(sym_in) + "\n" + str(self.state.callstack)
            self.returns = False
            print_error(error)
            return

        # bad object_id
        object_id = self.state.solver.eval(self.state.mem[object_id_pointer].string, cast_to=bytes)
        if object_id not in self.state.globals:
            return ReturnTypes.TEE_ERROR_ITEM_NOT_FOUND

        # Allocate memory for object_handle (0x11c)
        self.state.regs.r0 = 0x11c
        self.state.regs.r1 = 0x0
        self.inline_call(HookTeeMalloc)
        object_handle_memory = self.state.solver.eval(self.state.regs.r0)
        self.state.memory.store(object_handle_memory, b"E"*0x11c)

        # write address of object_handle to outbuf
        self.state.mem[object_pointer].int = object_handle_memory

        # Allocate memory for object_info (0x1c)
        self.state.regs.r0 = 0x1c
        self.state.regs.r1 = 0x0
        self.inline_call(HookTeeMalloc)
        object_info_memory = self.state.solver.eval(self.state.regs.r0)
        self.state.memory.store(object_info_memory, b"F" * 0x1c)

        # write address of object_info to object_handle
        self.state.mem[object_handle_memory + 0x108].int = object_info_memory

        # object_handle starts with pointer to itself, followed by objectIDLen
        self.state.mem[object_handle_memory].int = object_handle_memory
        self.state.mem[object_handle_memory + 0x4].int = object_id_len

        # write objectID to object_handle (followed by nullbyte)
        self.state.regs.r0 = object_handle_memory + 0x8
        self.state.regs.r1 = object_id_pointer
        self.state.regs.r2 = object_id_len
        self.inline_call(HookTeeMemMove)
        self.state.mem[object_handle_memory + object_id_len + 0x8].byte = 0x0

        # TODO: is this just one current_data_position counter for read and write or two seperate counters?
        # TODO: maybe the data_position value from object_info should be used
        """# write value to represent the current data_read_position
        self.state.mem[object_handle_memory + object_id_len + 0xc].int = 0x0

        # write value to represent the current data_write_position
        self.state.mem[object_handle_memory + object_id_len + 0x10].int = 0x0"""

        # write object_info data
        self.state.mem[object_info_memory].int = 0xA1000033             # object_type
        self.state.mem[object_info_memory + 0x4].int = 0x0              # object_size
        self.state.mem[object_info_memory + 0x8].int = 0xFFFFFFFF       # max_object_size
        self.state.mem[object_info_memory + 0xc].int = 0xFFFFFFFF       # object_usage
        self.state.mem[object_info_memory + 0x10].int = 0x0             # data_size
        self.state.mem[object_info_memory + 0x14].int = 0x0             # data_position
        self.state.mem[object_info_memory + 0x18].int = flags | 0x30000  # handle_flags

        # Allocate memory for object_info_append (0xc)
        self.state.regs.r0 = 0xc
        self.state.regs.r1 = 0x0
        self.inline_call(HookTeeMalloc)
        object_info_append_memory = self.state.solver.eval(self.state.regs.r0)
        self.state.memory.store(object_info_append_memory, b"G" * 0xc)

        # write address of object_info_append to object_handle
        self.state.mem[object_handle_memory + 0x118].int = object_info_append_memory

        return ReturnTypes.TEE_SUCCESS


class HookTeeCloseObject(angr.SimProcedure):
    SYMBOL = "TEE_CloseObject"

    # TODO: not yet tested, but should fill all bytes in relation to object_handle with zeros

    def run(self):
        object_pointer = self.state.solver.eval(self.state.regs.r0)

        # TODO: maybe this should be solved with a simple call to TEE_Free

        # remove object_info_append of object_handle
        self.state.regs.r0 = self.state.solver.eval(
            self.state.mem[object_pointer].int.resolved + 0x118)  # get pointer to object_info_append
        self.state.regs.r1 = b'\x00' * 0xC
        self.state.regs.r2 = 0xC
        self.inline_call(HookTeeMemMove)

        # remove object_info of object_handle
        self.state.regs.r0 = self.state.solver.eval(
            self.state.mem[object_pointer].int.resolved + 0x108)  # get pointer to object_info
        self.state.regs.r1 = b'\x00' * 0x1C
        self.state.regs.r2 = 0x1C
        self.inline_call(HookTeeMemMove)

        # remove content of object_handle
        self.state.regs.r0 = object_pointer
        self.state.regs.r1 = b'\x00' * 0x11C
        self.state.regs.r2 = 0x11C
        self.inline_call(HookTeeMemMove)


class HookTeeCloseAndDeletePersistentObject(angr.SimProcedure):
    SYMBOL = "TEE_CloseAndDeletePersistentObject"

    # TODO: not yet tested, but should work
    def run(self):
        object_pointer = self.state.solver.eval(self.state.regs.r0)

        # get flags from object_info in object_handle
        flags = get_object_handle_flags(self.state, object_pointer)

        # check flags, if object_handle has permission to delete the file
        if not flags & DataFlags.TEE_DATA_FLAG_ACCESS_WRITE_META:
            raise NoPermissionException("ObjectHandle does not have the rights to delete the file, but the corresponding"
                                      " behavior is not yet implemented!")

        # get object_id and remove entry from state.globals-dictt
        object_id = get_object_id(self.state, object_pointer)
        del self.state.globals[object_id]
        self.inline_call(HookTeeCloseObject)


class HookTeeAllocateOperation(angr.SimProcedure):
    SYMBOL = "TEE_AllocateOperation"

    def run(self):
        operation_pointer = self.state.solver.eval(self.state.regs.r0)
        algorithm = self.state.solver.eval(self.state.regs.r1)
        mode = self.state.solver.eval(self.state.regs.r2)
        maxKeySize = self.state.solver.eval(self.state.regs.r3)

        if algorithm == OperationAlgorithms.TEE_ALG_SHA256 and mode == OperationModes.TEE_MODE_DIGEST:
            op_c = 0
            # save a counter for operation_handles (so theoretically multiple operation handles can be stored)
            if 'operation_count' in self.state.globals:
                op_c = self.state.globals['operation_count']
                self.state.globals['operation_count'] += 1
            else:
                self.state.globals['operation_count'] = op_c + 1

            self.state.mem[operation_pointer].int = op_c

            operation_handle_id = 'op_'+str(op_c)
            hash_id = "hash_"+operation_handle_id
            # save operation_handle as string, since state.globals produces shallow copy only
            operation_handle = hex(algorithm)+"|"+hex(mode)+"|"+hex(maxKeySize)+"|"+hash_id
            self.state.globals[operation_handle_id] = operation_handle
            # states.globals produces shallow copy -> we store bytes to be hashed in dict
            # (concatenate on DigestUpdate()) and produce the hash on DoFinal()
            self.state.globals[hash_id] = b''
            return ReturnTypes.TEE_SUCCESS
        else:
            raise NotImplementedError("The desired algorithm or mode is not yet implemented!\nFeel free to do so! :)")


class HookDigestUpdate(angr.SimProcedure):
    SYMBOL = "TEE_DigestUpdate"

    def run(self):
        operation = self.state.solver.eval(self.state.regs.r0)
        chunk_pointer = self.state.solver.eval(self.state.regs.r1)
        chunk_size = self.state.solver.eval(self.state.regs.r2)

        operation_handle = extract_operation_handle(self.state, operation)
        chunk = self.state.solver.eval(self.state.memory.load(chunk_pointer, chunk_size), cast_to=bytes)    # TODO: check if chunk is really bytes
        self.state.globals[operation_handle[3]] += chunk


class HookDigestDoFinal(angr.SimProcedure):
    SYMBOL = "TEE_DigestDoFinal"

    def run(self):
        operation = self.state.solver.eval(self.state.regs.r0)
        chunk_pointer = self.state.solver.eval(self.state.regs.r1)
        chunk_size = self.state.solver.eval(self.state.regs.r2)
        hash_pointer = self.state.solver.eval(self.state.regs.r3)
        hash_len = self.state.solver.eval(self.state.mem[self.state.mem[self.state.regs.r13].int.resolved].int.resolved)

        operation_handle = extract_operation_handle(self.state, operation)
        chunk = self.state.solver.eval(self.state.memory.load(chunk_pointer, chunk_size), cast_to=bytes)    # TODO: check if chunk is really bytes
        self.state.globals[operation_handle[3]] += chunk
        final_hash = hashlib.sha256(self.state.globals[operation_handle[3]]).digest()
        if len(final_hash) > hash_len:
            return ReturnTypes.TEE_ERROR_SHORT_BUFFER
        # store the final hash to hash_pointer location
        self.state.memory.store(hash_pointer, final_hash)
        # reset the message digest operation
        self.state.globals[operation_handle[3]] = b''
        return ReturnTypes.TEE_SUCCESS


class HookFreeOperation(angr.SimProcedure):
    SYMBOL = "TEE_FreeOperation"

    def run(self):
        operation = self.state.solver.eval(self.state.regs.r0)
        operation_handle = extract_operation_handle(self.state, operation)
        # delete the message digest operation
        del self.state.globals[operation_handle[3]]
        # delete the operation handle
        del self.state.globals['op_'+str(operation)]


class HookTeeReadObjectData(angr.SimProcedure):
    SYMBOL = "TEE_ReadObjectData"

    def run(self):
        """ this function does nothing. """
        # not 100% sure if the first argument is a pointer or not, but it is not important,
        #  since the first dword of the object handle is a pointer to itself
        object_pointer = self.state.solver.eval(self.state.regs.r0)
        buffer_pointer = self.state.solver.eval(self.state.regs.r1)
        size = self.state.solver.eval(self.state.regs.r2)
        count_pointer = self.state.solver.eval(self.state.regs.r3)

        # get flags from object_info in object_handle
        flags = get_object_handle_flags(self.state, object_pointer)

        if not flags & DataFlags.TEE_DATA_FLAG_ACCESS_READ:
            raise NoPermissionException("ObjectHandle does not have the rights to read the file, but the corresponding"
                                      " behavior is not yet implemented!")

        data = self.state.globals[get_object_id(self.state, object_pointer)]
        data_position = get_data_position(self.state, object_pointer)
        if data_position >= len(data):
            # if data_position is at or beyond end-of-file, no bytes are read
            read_data = b''
            read_data_len = 0
        else:
            # if data_position to end-of-file is less than size, bytes up to end-of-file are read
            read_data_len = min(size, len(data)-data_position)
            read_data = data[data_position:data_position+read_data_len]

        # store results in outbufs
        self.state.memory.store(buffer_pointer, read_data)
        self.state.mem[count_pointer].int = read_data_len

        # update data_position
        set_data_position(self.state, object_pointer, data_position+read_data_len)

        return ReturnTypes.TEE_SUCCESS


class HookTeeWriteObjectData(angr.SimProcedure):
    SYMBOL = "TEE_WriteObjectData"

    def run(self):
        """ this function does nothing. """
        # not 100% sure if the first argument is a pointer or not, but it is not important,
        #  since the first dword of the object handle is a pointer to itself
        object_pointer = self.state.solver.eval(self.state.regs.r0)
        buffer_pointer = self.state.solver.eval(self.state.regs.r1)
        size = self.state.solver.eval(self.state.regs.r2)

        # get flags from object_info in object_handle
        flags = get_object_handle_flags(self.state, object_pointer)

        if not flags & DataFlags.TEE_DATA_FLAG_ACCESS_WRITE:
            raise NoPermissionException("ObjectHandle does not have the rights to write to the file, but the"
                                      " corresponding behavior is not yet implemented!")

        # TODO: implement WriteObjectData when it's clear what data_position and data_sizes to use...
        object_id = get_object_id(self.state, object_pointer)
        data_size = get_data_size(self.state, object_pointer)
        data_position = get_data_position(self.state, object_pointer)
        input_data = self.state.solver.eval(self.state.memory.load(buffer_pointer, size), cast_to=bytes)

        # if data_position points beyond the end-of-stream, the file is extended with zeros and the buffer is appended
        # data_size and data_position are increased accordingly
        if data_position > data_size:
            extension_size = data_position-data_size
            input_data = b'\x00'*extension_size + input_data

        self.state.globals[object_id] += input_data
        set_data_position(self.state, object_pointer, data_position + size)
        set_data_size(self.state, object_pointer, data_position + size)

        return ReturnTypes.TEE_SUCCESS


class HookTeeSeekObjectData(angr.SimProcedure):
    SYMBOL = "TEE_SeekObjectData"

    # TODO: maybe add check if TEE_DATA_MAX_POSITION is exceeded
    def run(self):
        """ this function does nothing. """
        object_pointer = self.state.solver.eval(self.state.regs.r0)
        offset = self.state.solver.eval(self.state.regs.r1)
        whence = self.state.solver.eval(self.state.regs.r2)

        if whence == TeeWhence.TEE_DATA_SEEK_SET:
            set_data_position(self.state, object_pointer, offset)
        elif whence == TeeWhence.TEE_DATA_SEEK_CUR:
            data_position = get_data_position(self.state, object_pointer)
            set_data_position(self.state, object_pointer, data_position+offset)
        elif whence == TeeWhence.TEE_DATA_SEEK_END:
            data_size = get_data_size(self.state, object_pointer)
            set_data_position(self.state, object_pointer, data_size + offset)
        else:
            raise Exception("Bad TEE_Whence provided to SeekObjectData function!")

        return ReturnTypes.TEE_SUCCESS
