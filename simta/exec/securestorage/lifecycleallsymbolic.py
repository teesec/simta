import angr, claripy
from simta.securestoragehooks import UserInput, MAX_STRLEN, LifecycleCommandIds, InvokeCommandIds, DataFlags, TeeWhence
from simta.tcparams import TCParams, TCParam, TEECParamType, TypeCategories
from .lifecycle import SecureStorageLifecycle


class SecureStorageLifecycleAllSymbolic(SecureStorageLifecycle):

    def __init__(self):
        super(SecureStorageLifecycle, self).__init__()
        self._setup()

    def _setup(self):
        self.append(self.open_session)
        self.append(self.fopen)
        self.append(self.fwrite)
        self.append(self.fseek)
        self.append(self.fread)
        self.append(self.fclose)
        self.append(self.close_session)

    @classmethod
    def store_symbolic_variable(cls, state, var):
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

    @classmethod
    def store_symbolic_params(cls, state, params):
        # reset state_symbolics for each function call
        state.globals['state_symbolics'] = ""
        for param in params:
            if param.watch:
                for variable in vars(param):
                    var = getattr(param, variable)
                    if type(var) is claripy.ast.bv.BV:
                        if var.symbolic:
                            cls.store_symbolic_variable(state, var)

    @classmethod
    def open_session(cls, state):
        """
        start execution with completely symbolic input
        -when a breakpoint is reached, check the constraints and set the input accordingly (or add complementary constraint to inputs to find new ways)
        -when errors occur, check what inputs they depend on; (mostly these inputs have to be memref_inputs)
            -adjust the input parameters and restart the program
        """

        # 1st Lifecycle: TA_OpenSessionEntryPoint
        lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.OPEN_SESSION, 32).append_annotation(UserInput("lifecycle_cmd_id"))  # cmd_id for OpenSession

        param0 = cls.create_empty_param("opensession_0", True)
        param1 = cls.create_empty_param("opensession_1", True)
        param2 = cls.create_empty_param("opensession_2", True)
        param3 = cls.create_empty_param("opensession_3", True)


        param3_len = claripy.BVS("param3_len_opensession", 32).append_annotation(
            UserInput("param3_len_open_session"))  # -1 because of nullbyte
        state.solver.add(claripy.And(param3_len >= 0, param3_len <= MAX_STRLEN))
        param3_buf = claripy.BVS("param3_buf_opensession", MAX_STRLEN * 8).append_annotation(UserInput("param3_buf_open_session"))
        param3_type = claripy.BVV(TEECParamType.TEEC_MEMREF_TEMP_INPUT, 16).append_annotation(
            UserInput("param3_type_open_session"))

        param2_len = claripy.BVS("param2_len_opensession", 32).append_annotation(
            UserInput("param2_len_open_session"))  # -1 because of nullbyte
        state.solver.add(claripy.And(param2_len >= 0, param2_len <= MAX_STRLEN))
        param2_buf = claripy.BVS("param2_buf_opensession", MAX_STRLEN * 8).append_annotation(
            UserInput("param2_buf_open_session"))
        param2_type = claripy.BVV(TEECParamType.TEEC_MEMREF_TEMP_INPUT, 16).append_annotation(
            UserInput("param2_type_open_session"))

        """param3_buf = claripy.BVV(b"/system/bin/tee_test_store\x00", 27 * 8).append_annotation(UserInput("param3_buf_open_session"))
        param3_len = claripy.BVV(26, 32).append_annotation(
            UserInput("param3_len_open_session"))  # -1 because of nullbyte"""

        param3 = TCParam(param3_type, param3_buf, param3_len, True)
        param2 = TCParam(param2_type, param2_buf, param2_len, True)

        params = TCParams(param0, param1, param2, param3)
        invoke_cmd_id = 0
        cls.store_symbolic_params(state, params)
        param_types = claripy.ZeroExt(16, params.get_param_type())  # param_types has 16 bit, but needs to be extended to architecture size
        state.solver.add((claripy.LShR(param_types, 0xc) & 0xf) - 0x5 <= 0x2)
        state.solver.add(claripy.LShR(param3_buf, MAX_STRLEN*8-26*8) != 0x2f73797374656d2f62696e2f7465655f746573745f73746f7265)
        # TODO: store param_types to symbolics here
        cls.prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)

    @classmethod
    def fopen(cls, state):
        """ 2nd Lifecycle: TA_InvokeCommandEntryPoint (FOPEN) """
        lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.INVOKE_COMMAND, 32).append_annotation(UserInput("lifecycle_cmd_id"))  # cmd_id for InvokeCommand
        invoke_cmd_id = claripy.BVV(InvokeCommandIds.FOPEN, 32).append_annotation(UserInput("invoke_cmd_id"))  # cmd_id for FOPEN in InvokeCommand

        param0 = cls.create_empty_param("fopen_0", True)
        param1 = cls.create_empty_param("fopen_1", True)
        param2 = cls.create_empty_param("fopen_2", True)
        param3 = cls.create_empty_param("fopen_3", True)

        """param0_len = claripy.BVS("param0_len_fopen", 32).append_annotation(
            UserInput("param0_len_fopen"))
        state.solver.add(claripy.And(param0_len >= 0, param0_len <= MAX_STRLEN))
        param0_buf = claripy.BVS("param0_buf_fopen", MAX_STRLEN * 8).append_annotation(UserInput("param0_buf_fopen"))
        param0_type = claripy.BVV(TEECParamType.TEEC_MEMREF_TEMP_INPUT, 16).append_annotation(
            UserInput("param0_type_fopen"))

        param0 = TCParam(param0_type, param0_buf, param0_len)

        param1_a = claripy.BVV(DataFlags.TEE_DATA_FLAG_ACCESS_READ | DataFlags.TEE_DATA_FLAG_ACCESS_WRITE | DataFlags.TEE_DATA_FLAG_CREATE, 32).append_annotation(UserInput("param1_a_fopen_flags"))
        param1_b = claripy.BVV(0, 32).append_annotation(UserInput("param1_b_fopen"))
        param1_type = claripy.BVV(TEECParamType.TEEC_VALUE_INPUT, 16).append_annotation(
            UserInput("param1_type_fopen"))

        param1 = TCParam(param1_type, param1_a, param1_b)"""

        params = TCParams(param0, param1, param2, param3)
        cls.store_symbolic_params(state, params)

        param_types = claripy.ZeroExt(16, params.get_param_type())
        cls.prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)

    @classmethod
    def fwrite(cls, state):
        """ 3rd Lifecycle: TA_InvokeCommandEntryPoint (FWRITE) """
        lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.INVOKE_COMMAND, 32).append_annotation(UserInput("lifecycle_cmd_id"))  # cmd_id for InvokeCommand
        invoke_cmd_id = claripy.BVV(InvokeCommandIds.FWRITE, 32).append_annotation(UserInput("invoke_cmd_id"))  # cmd_id for FREAD in InvokeCommand

        param0 = cls.create_empty_param("fwrite_0", True)
        param1 = cls.create_empty_param("fwrite_1", True)
        param2 = cls.create_empty_param("fwrite_2", True)
        param3 = cls.create_empty_param("fwrite_3", True)

        params = TCParams(param0, param1, param2, param3)
        cls.store_symbolic_params(state, params)

        param_types = claripy.ZeroExt(16, params.get_param_type())
        cls.prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)

    @classmethod
    def fseek(cls, state):
        """ 4th Lifecycle: TA_InvokeCommandEntryPoint (FSEEK) """
        lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.INVOKE_COMMAND, 32).append_annotation(UserInput("lifecycle_cmd_id"))  # cmd_id for InvokeCommand
        invoke_cmd_id = claripy.BVV(InvokeCommandIds.FSEEK, 32).append_annotation(UserInput("invoke_cmd_id"))  # cmd_id for FREAD in InvokeCommand

        param0 = cls.create_empty_param("fseek_0", True)
        param1 = cls.create_empty_param("fseek_1", True)
        param2 = cls.create_empty_param("fseek_2", True)
        param3 = cls.create_empty_param("fseek_3", True)

        params = TCParams(param0, param1, param2, param3)
        cls.store_symbolic_params(state, params)

        param_types = claripy.ZeroExt(16, params.get_param_type())
        cls.prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)

    @classmethod
    def fread(cls, state):
        """ 5th Lifecycle: TA_InvokeCommandEntryPoint (FREAD) """
        lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.INVOKE_COMMAND, 32).append_annotation(UserInput("lifecycle_cmd_id"))  # cmd_id for InvokeCommand
        invoke_cmd_id = claripy.BVV(InvokeCommandIds.FREAD, 32).append_annotation(UserInput("invoke_cmd_id"))  # cmd_id for FREAD in InvokeCommand

        param0 = cls.create_empty_param("fread_0")
        param1 = cls.create_empty_param("fread_1")
        param2 = cls.create_empty_param("fread_2")
        param3 = cls.create_empty_param("fread_3")

        params = TCParams(param0, param1, param2, param3)
        cls.store_symbolic_params(state, params)

        param_types = claripy.ZeroExt(16, params.get_param_type())
        cls.prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)

    @classmethod
    def fclose(cls, state):
        """ 6th Lifecycle: TA_InvokeCommandEntryPoint (CLOSE) """
        lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.INVOKE_COMMAND, 32).append_annotation(UserInput("lifecycle_cmd_id"))  # cmd_id for InvokeCommand
        invoke_cmd_id = claripy.BVV(InvokeCommandIds.FCLOSE, 32).append_annotation(UserInput("invoke_cmd_id"))  # cmd_id for FCLOSE in InvokeCommand

        param0 = cls.create_empty_param("fclose_0", True)
        param1 = cls.create_empty_param("fclose_1", True)
        param2 = cls.create_empty_param("fclose_2", True)
        param3 = cls.create_empty_param("fclose_3", True)

        params = TCParams(param0, param1, param2, param3)
        cls.store_symbolic_params(state, params)

        param_types = claripy.ZeroExt(16, params.get_param_type())
        cls.prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)

    @classmethod
    def close_session(cls, state):
        """ 7th Lifecylce: TA_CloseSessionEntryPoint """
        lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.CLOSE_SESSION, 32).append_annotation(UserInput("lifecycle_cmd_id"))  # cmd_id for CloseSession

        param0 = cls.create_empty_param()
        param1 = cls.create_empty_param()
        param2 = cls.create_empty_param()
        param3 = cls.create_empty_param()

        params = TCParams(param0, param1, param2, param3)
        invoke_cmd_id = 0
        cls.store_symbolic_params(state, params)

        param_types = claripy.ZeroExt(16, params.get_param_type())
        cls.prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)

