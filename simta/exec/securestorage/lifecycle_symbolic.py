import angr, claripy
from securestoragehooks import UserInput, MAX_STRLEN, LifecycleCommandIds, InvokeCommandIds, DataFlags, TeeWhence
from tcparams import TCParams, TCParam, TEECParamType, TypeCategories
from securestorage import SecureStorage
import struct


# NOTE: angr does not support anonymous members of unions, this is why we named the structs here
# you can access them like this:
#   self.state.mem[addr].TC_NS_Parameter.struct.memref
#   self.state.mem[addr].TC_NS_Parameter.struct.value
if not "TC_NS_Parameter" in angr.types.ALL_TYPES:
    tc_ns_parameter = angr.types.parse_types("""
                typedef union
                {
                    struct memref
                    {
                        unsigned int buffer;
                        unsigned int size;
                    };
                    struct value
                    {
                        unsigned int a;
                        unsigned int b;
                    };
                } TC_NS_Parameter;
            """)
    angr.types.register_types(tc_ns_parameter)


CALL_SEQUENCE = []


def create_empty_param(name_appendix="empty", watch=False):
    param_a = claripy.BVS("param_a_"+name_appendix, 32).append_annotation(UserInput("param_a_"+name_appendix))
    param_b = claripy.BVS("param_b_"+name_appendix, 32).append_annotation(UserInput("param_b_"+name_appendix))
    param_type = claripy.BVS("param_type_"+name_appendix, 16).append_annotation(UserInput("param_type_"+name_appendix))
    return TCParam(param_type, param_a, param_b, watch)


def store_symbolic_variable(state, var):
    """
    since state.globals produces shallow copies, when state is forked, we need to keep track of the symbolic
    variables of the current state only
    """
    state.globals['all_symbolics'][var.args[0]] = var

    appendix = var.args[0]
    if state.globals['state_symbolics'] == "":
        state.globals['state_symbolics'] = appendix
    else:
        state.globals['state_symbolics'] += "|" + appendix


def store_symbolic_params(state, params):
    for param in params:
        if param.watch:
            for variable in vars(param):
                var = getattr(param, variable)
                if type(var) is claripy.ast.bv.BV:
                    if var.symbolic:
                        store_symbolic_variable(state, var)


def prepare_msg_recv_return(state, lifecycle_cmd_id, invoke_cmd_id, param_types, params):
    """ r1 -> pointer to stack where lifecycle_cmd_id is located
        r2 -> [r2+2] cmd_id, [r2+3] paramTypes, [r2+4] params
    """
    state.globals["lifecycle_cmd_id"] = lifecycle_cmd_id
    state.globals["invoke_cmd_id"] = invoke_cmd_id

    shm_params_memref = state.mem[SecureStorage.shared_mem_base].TC_NS_Parameter.struct.memref.array(4)
    shm_params_value = state.mem[SecureStorage.shared_mem_base].TC_NS_Parameter.struct.value.array(4)

    for i, param in enumerate(params):
        if param.get_type_category() == TypeCategories.NoneType:
            # type is none, we can skip this param
            continue
        elif param.get_type_category() == TypeCategories.ValueType:
            shm_params_value[i].a = param.a_or_buf
            shm_params_value[i].b = param.b_or_sz
            # raise NotImplementedError("Implement me!")
        elif param.get_type_category() == TypeCategories.MemrefType:
            # increased buffer-size to 0x120, because signature needs 0x109 bytes
            param_ptr = claripy.BVV(SecureStorage.shared_mem_base + (0x100+0x120*i), 32).append_annotation(UserInput("param{}_ptr".format(i)))
            state.memory.store(param_ptr, param.a_or_buf)
            shm_params_memref[i].buffer = param_ptr
            shm_params_memref[i].size = param.b_or_sz
        else:
            raise TEECParamType.UnknownParamTypeException("Unknown param type {}".format(param.type))


    # write lifecycle_cmd_id to r1
    state.mem[state.regs.r1].int = lifecycle_cmd_id

    # write cmd_id, param_types, and params pointer to r2 + x
    state.mem[state.regs.r2 + claripy.BVV(0x8, 32)].int = invoke_cmd_id
    state.mem[state.regs.r2 + claripy.BVV(0xc, 32)].int = param_types
    state.mem[state.regs.r2 + claripy.BVV(0x10, 32)].int = claripy.BVV(SecureStorage.shared_mem_base, 32) \
        .append_annotation(UserInput("params_struct_pointer"))

    """ Try to place sessionContext somewhere, where it will be accessed """
    if 'sessionContext' in state.globals:
        state.mem[state.regs.r2 + claripy.BVV(0x14, 32)].int = state.globals['sessionContext']
        #print(state.mem[state.regs.r2 + claripy.BVV(0x14, 32)].int)


def open_session(state):

    # 1st Lifecycle: TA_OpenSessionEntryPoint
    lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.OPEN_SESSION, 32).append_annotation(UserInput("lifecycle_cmd_id"))  # cmd_id for OpenSession

    param2_len = claripy.BVS("param2_len", 32).append_annotation(UserInput("param2_len_open_session"))
    param3_len = claripy.BVS("param3_len", 32).append_annotation(UserInput("param3_len_open_session"))  # -1 because of nullbyte
    state.solver.add(claripy.And(param2_len >= 0, param2_len <= MAX_STRLEN))
    state.solver.add(claripy.And(param3_len >= 0, param3_len <= MAX_STRLEN))

    param2_buf = claripy.BVS("param2_buf", MAX_STRLEN * 8).append_annotation(UserInput("param2_buf_open_session"))
    param3_buf = claripy.BVS("param3_buf", MAX_STRLEN * 8).append_annotation(UserInput("param3_buf_open_session"))

    param2_type = claripy.BVV(TEECParamType.TEEC_MEMREF_TEMP_INPUT, 16).append_annotation(
        UserInput("param2_type_open_session"))
    param3_type = claripy.BVV(TEECParamType.TEEC_MEMREF_TEMP_INPUT, 16).append_annotation(
        UserInput("param3_type_open_session"))
    """
    param2_type = claripy.BVS("param2_type", 16).append_annotation(UserInput("param2_type_open_session"))
    param3_type = claripy.BVS("param3_type", 16).append_annotation(UserInput("param3_type_open_session"))
    """

    param0 = TCParam(TEECParamType.TEEC_NONE, None, None)
    param1 = TCParam(TEECParamType.TEEC_NONE, None, None)
    param2 = TCParam(param2_type, param2_buf, param2_len, True)
    param3 = TCParam(param3_type, param3_buf, param3_len, True)

    params = TCParams(param0, param1, param2, param3)
    invoke_cmd_id = 0
    store_symbolic_params(state, params)
    param_types = claripy.ZeroExt(16, params.get_param_type())  # param_types has 16 bit, but needs to be extended to architecture size
    # TODO: store param_types to symbolics here
    prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)


CALL_SEQUENCE.append(open_session)


def fopen(state):

    # 2nd Lifecycle: TA_InvokeCommandEntryPoint
    # FOPEN
    lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.INVOKE_COMMAND, 32).append_annotation(UserInput("lifecycle_cmd_id"))  # cmd_id for InvokeCommand
    invoke_cmd_id = claripy.BVV(InvokeCommandIds.FOPEN, 32).append_annotation(UserInput("invoke_cmd_id"))  # cmd_id for FOPEN in InvokeCommand

    param0_buf = b"sec_storage_data/test\x00"
    param0_len = claripy.BVV(len(param0_buf) - 1, 32).append_annotation(UserInput(src="param0_len_fopen"))  # -1 because of nullbyte
    param0_buf = claripy.BVV(param0_buf, len(param0_buf) * 8).append_annotation(UserInput("param0_buf_fopen"))
    param0_type = claripy.BVV(TEECParamType.TEEC_MEMREF_TEMP_INPUT, 16).append_annotation(UserInput("param0_type_fopen"))

    param1_a = claripy.BVV(
        DataFlags.TEE_DATA_FLAG_ACCESS_READ | DataFlags.TEE_DATA_FLAG_ACCESS_WRITE | DataFlags.TEE_DATA_FLAG_CREATE,
        32).append_annotation(UserInput("param1_a_fopen_flags"))
    param1_b = claripy.BVV(0, 32).append_annotation(UserInput("param1_b_fopen"))
    param1_type = claripy.BVV(TEECParamType.TEEC_VALUE_INPUT, 16).append_annotation(
        UserInput("param1_type_fopen"))

    param0 = TCParam(param0_type, param0_buf, param0_len)
    param1 = TCParam(param1_type, param1_a, param1_b)


    param0 = create_empty_param("fopen_0", True)
    param1 = create_empty_param("fopen_1", True)
    param2 = create_empty_param("fopen_2", True)
    param3 = create_empty_param("fopen_3", True)

    params = TCParams(param0, param1, param2, param3)
    store_symbolic_params(state, params)

    param_types = claripy.ZeroExt(16, params.get_param_type())
    prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)


CALL_SEQUENCE.append(fopen)


def fwrite(state):

    # 3rd Lifecycle: TA_InvokeCommandEntryPoint
    # FREAD
    lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.INVOKE_COMMAND, 32).append_annotation(UserInput("lifecycle_cmd_id"))  # cmd_id for InvokeCommand
    invoke_cmd_id = claripy.BVV(InvokeCommandIds.FWRITE, 32).append_annotation(UserInput("invoke_cmd_id"))  # cmd_id for FREAD in InvokeCommand

    # TODO: dynamically pass fopen-memory-address via msg_snd/msg_rcv (if possible)
    param0_a = state.globals['current_object_handle_ptr'].append_annotation(UserInput("param0_a_fwrite"))  # needs to be set to the memory, where the file was opened with f_open
    param0_b = claripy.BVV(0x0, 32).append_annotation(UserInput("param0_b_fwrite"))
    param0_type = claripy.BVV(TEECParamType.TEEC_VALUE_INPUT, 16).append_annotation(UserInput("param0_type_fwrite"))

    param1_a = claripy.BVV(b'Ich schreib was ich will!', 0x19 * 8).append_annotation(
        UserInput("param1_a_fwrite_inbuf"))  # needs to be set to the memory, where the file was opened with f_open
    param1_b = claripy.BVV(0x19, 32).append_annotation(UserInput("param1_b_fwrite_insize"))
    param1_type = claripy.BVV(TEECParamType.TEEC_MEMREF_TEMP_INPUT, 16).append_annotation(
        UserInput("param1_type_fwrite"))

    param0 = TCParam(param0_type, param0_a, param0_b)
    param1 = TCParam(param1_type, param1_a, param1_b, True)
    param2 = create_empty_param("fwrite_2")
    param3 = create_empty_param("fwrite_3")

    params = TCParams(param0, param1, param2, param3)
    store_symbolic_params(state, params)

    param_types = claripy.ZeroExt(16, params.get_param_type())
    prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)


CALL_SEQUENCE.append(fwrite)


def fseek(state):

    # 3rd Lifecycle: TA_InvokeCommandEntryPoint
    # FREAD
    lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.INVOKE_COMMAND, 32).append_annotation(UserInput("lifecycle_cmd_id"))  # cmd_id for InvokeCommand
    invoke_cmd_id = claripy.BVV(InvokeCommandIds.FSEEK, 32).append_annotation(UserInput("invoke_cmd_id"))  # cmd_id for FREAD in InvokeCommand

    # TODO: dynamically pass fopen-memory-address via msg_snd/msg_rcv (if possible)
    param0_a = state.globals['current_object_handle_ptr'].append_annotation(
        UserInput("param0_a_fseek_obj_handle"))  # needs to be set to the memory, where the file was opened with f_open
    param0_b = claripy.BVV(0x0, 32).append_annotation(UserInput("param0_b_fseek_offset"))
    param0_type = claripy.BVV(TEECParamType.TEEC_VALUE_INPUT, 16).append_annotation(UserInput("param0_type_fseek"))

    param1_a = claripy.BVV(TeeWhence.TEE_DATA_SEEK_SET, 32).append_annotation(
        UserInput("param1_a_fseek_whence"))  # needs to be set to the memory, where the file was opened with f_open
    param1_b = claripy.BVV(0x0, 32).append_annotation(UserInput("param1_b_fseek"))
    param1_type = claripy.BVV(TEECParamType.TEEC_VALUE_INPUT, 16).append_annotation(
        UserInput("param1_type_fseek"))

    param0 = TCParam(param0_type, param0_a, param0_b)
    param1 = TCParam(param1_type, param1_a, param1_b)
    param2 = create_empty_param("fseek_2", True)
    param3 = create_empty_param("fseek_3", True)

    params = TCParams(param0, param1, param2, param3)
    store_symbolic_params(state, params)

    param_types = claripy.ZeroExt(16, params.get_param_type())
    prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)


CALL_SEQUENCE.append(fseek)


def fread(state):

    # 3rd Lifecycle: TA_InvokeCommandEntryPoint
    # FREAD
    lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.INVOKE_COMMAND, 32).append_annotation(UserInput("lifecycle_cmd_id"))  # cmd_id for InvokeCommand
    invoke_cmd_id = claripy.BVV(InvokeCommandIds.FREAD, 32).append_annotation(UserInput("invoke_cmd_id"))  # cmd_id for FREAD in InvokeCommand

    # TODO: dynamically pass fopen-memory-address via msg_snd/msg_rcv (if possible)
    param0_a = state.globals['current_object_handle_ptr'].append_annotation(UserInput("param0_a_fread"))  # needs to be set to the memory, where the file was opened with f_open
    param0_b = claripy.BVV(0x0, 32).append_annotation(UserInput("param0_b_fread"))
    param0_type = claripy.BVV(TEECParamType.TEEC_VALUE_INPUT, 16).append_annotation(UserInput("param0_type_fread"))

    param1_a = claripy.BVV(0xc8022000, 32).append_annotation(
        UserInput("param1_a_fread_outbuf"))  # needs to be set to the memory, where the file was opened with f_open
    param1_b = claripy.BVV(0xf, 32).append_annotation(UserInput("param1_b_fread_outsize"))
    param1_type = claripy.BVV(TEECParamType.TEEC_MEMREF_TEMP_OUTPUT, 16).append_annotation(
        UserInput("param1_type_fread"))

    param0 = TCParam(param0_type, param0_a, param0_b)
    param1 = TCParam(param1_type, param1_a, param1_b, True)
    param2 = create_empty_param("fread_2")
    param3 = create_empty_param("fread_3")

    params = TCParams(param0, param1, param2, param3)
    store_symbolic_params(state, params)

    param_types = claripy.ZeroExt(16, params.get_param_type())
    prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)


CALL_SEQUENCE.append(fread)


def fclose(state):

    # 4th Lifecycle: TA_InvokeCommandEntryPoint
    # FCLOSE
    lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.INVOKE_COMMAND, 32).append_annotation(UserInput("lifecycle_cmd_id"))  # cmd_id for InvokeCommand
    invoke_cmd_id = claripy.BVV(InvokeCommandIds.FCLOSE, 32).append_annotation(UserInput("invoke_cmd_id"))  # cmd_id for FCLOSE in InvokeCommand

    param0_a = state.globals['current_object_handle_ptr'].append_annotation(
        UserInput("param0_a_fclose"))  # needs to be set to the memory, where the file was opened with f_open
    param0_b = claripy.BVV(0x0, 32).append_annotation(UserInput("param0_b_fclose"))
    param0_type = claripy.BVV(TEECParamType.TEEC_VALUE_INPUT, 16).append_annotation(UserInput("param0_type_fclose"))

    param0 = TCParam(param0_type, param0_a, param0_b)
    param1 = create_empty_param("fclose_1", True)
    param2 = create_empty_param("fclose_2", True)
    param3 = create_empty_param("fclose_3", True)

    params = TCParams(param0, param1, param2, param3)
    store_symbolic_params(state, params)

    param_types = claripy.ZeroExt(16, params.get_param_type())
    prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)


CALL_SEQUENCE.append(fclose)


def close_session(state):

    # 5th Lifecylce: TA_CloseSessionEntryPoint
    lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.CLOSE_SESSION, 32).append_annotation(UserInput("lifecycle_cmd_id"))  # cmd_id for CloseSession

    param0 = create_empty_param()
    param1 = create_empty_param()
    param2 = create_empty_param()
    param3 = create_empty_param()

    params = TCParams(param0, param1, param2, param3)
    invoke_cmd_id = 0
    store_symbolic_params(state, params)

    param_types = claripy.ZeroExt(16, params.get_param_type())
    prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)


CALL_SEQUENCE.append(close_session)
