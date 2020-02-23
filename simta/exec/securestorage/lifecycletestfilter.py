import struct

import angr, claripy
from simta.securestoragehooks import UserInput, MAX_STRLEN, LifecycleCommandIds, InvokeCommandIds, DataFlags, TeeWhence
from simta.tcparams import TCParams, TCParam, TEECParamType, TypeCategories
from .lifecycle import SecureStorageLifecycle


class SecureStorageLifecycleTestFilter(SecureStorageLifecycle):

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
    def open_session(cls, state):
        """ 1st Lifecycle: TA_OpenSessionEntryPoint """
        lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.OPEN_SESSION, 32).append_annotation(
            UserInput("lifecycle_cmd_id"))  # cmd_id for OpenSession

        test = False
        if test:
            param2_buf = b"\x00\x00\x00\x00"
            param3_buf = b"/system/bin/tee_test_store\x00"
        else:
            signature = "" \
                        + "E02C5AB97A2B3A8A5996223CDE06B82B2D4FF5B15CAF65B860D5C7A3D68995AB08620BB75A22FE7673A8A1ABA03E17B651D1FC4D5CBDBAE9E7" \
                        + "3EEEAF5A1D4D2FB73E7000231E0DB2166D0FC5DD97E705FD66546C9DA38ED4EFA2CCCDD238AD32E39821242B0195DF01D9B97242DBF209EDA8" \
                        + "E446E043244B84E6BFCA79D7BB3C1924CDD248EDBD600EFF8F73001A89A4C663DB8970E3288B9431524C361E853B8FA29E04E61EBE6FBDBD87" \
                        + "CDBD3EEB47B027B5851BDEAA13A23F43967A030E747EA432652CBB34FDDE61049BF5060C813FB0E93F6BAD9D36F4D4551195EA3BB49E9201AA" \
                        + "6DF975AE169E214905DE2579D7CC3C3EAC4594B14AC19D7E39C5C267"
            signature_bytes = bytes.fromhex(signature)
            exponent = struct.pack("<I", 0x0) + b"\x03"
            param2_buf = struct.pack("<I", len(signature_bytes)) + signature_bytes + exponent

            param3_buf = b"com.huawei.hidisk\x00"

        param2_len = claripy.BVV(len(param2_buf), 32).append_annotation(UserInput("param2_len_open_session"))
        param3_len = claripy.BVV(len(param3_buf) - 1, 32).append_annotation(
            UserInput("param3_len_open_session"))  # -1 because of nullbyte

        param2_buf = claripy.BVV(param2_buf, len(param2_buf) * 8).append_annotation(
            UserInput("param2_buf_open_session"))
        param3_buf = claripy.BVV(param3_buf, len(param3_buf) * 8).append_annotation(
            UserInput("param3_buf_open_session"))

        param2_type = claripy.BVV(TEECParamType.TEEC_MEMREF_TEMP_INPUT, 16).append_annotation(
            UserInput("param2_type_open_session"))
        param3_type = claripy.BVV(TEECParamType.TEEC_MEMREF_TEMP_INPUT, 16).append_annotation(
            UserInput("param3_type_open_session"))

        param0 = TCParam(TEECParamType.TEEC_NONE, None, None)
        param1 = TCParam(TEECParamType.TEEC_NONE, None, None)
        param2 = TCParam(param2_type, param2_buf, param2_len)
        param3 = TCParam(param3_type, param3_buf, param3_len)

        params = TCParams(param0, param1, param2, param3)
        invoke_cmd_id = 0
        param_types = claripy.ZeroExt(16, params.get_param_type())
        cls.prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)

    @classmethod
    def fopen(cls, state):
        """ 2nd Lifecycle: TA_InvokeCommandEntryPoint (FOPEN) """
        lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.INVOKE_COMMAND, 32).append_annotation(
            UserInput("lifecycle_cmd_id"))  # cmd_id for InvokeCommand
        invoke_cmd_id = claripy.BVV(InvokeCommandIds.FOPEN, 32).append_annotation(
            UserInput("invoke_cmd_id"))  # cmd_id for FOPEN in InvokeCommand

        param0_buf = b"sec_storage_data/test\x00"
        param0_len = claripy.BVV(len(param0_buf) - 1, 32).append_annotation(
            UserInput(src="param0_len_fopen"))  # -1 because of nullbyte
        param0_buf = claripy.BVV(param0_buf, len(param0_buf) * 8).append_annotation(UserInput("param0_buf_fopen"))
        param0_type = claripy.BVV(TEECParamType.TEEC_MEMREF_TEMP_INPUT, 16).append_annotation(
            UserInput("param0_type_fopen"))

        param1_a = claripy.BVV(
            DataFlags.TEE_DATA_FLAG_ACCESS_READ | DataFlags.TEE_DATA_FLAG_ACCESS_WRITE | DataFlags.TEE_DATA_FLAG_CREATE,
            32).append_annotation(UserInput("param1_a_fopen_flags"))
        param1_b = claripy.BVV(0, 32).append_annotation(UserInput("param1_b_fopen"))
        param1_type = claripy.BVV(TEECParamType.TEEC_VALUE_INPUT, 16).append_annotation(
            UserInput("param1_type_fopen"))

        param0 = TCParam(param0_type, param0_buf, param0_len)
        param1 = TCParam(param1_type, param1_a, param1_b)
        param2 = cls.create_empty_param()
        param3 = TCParam(TEECParamType.TEEC_NONE, None, None)

        params = TCParams(param0, param1, param2, param3)
        param_types = claripy.ZeroExt(16, params.get_param_type())
        cls.prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)

    @classmethod
    def fwrite(cls, state):
        """ 3rd Lifecycle: TA_InvokeCommandEntryPoint (FWRITE) """
        lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.INVOKE_COMMAND, 32).append_annotation(
            UserInput("lifecycle_cmd_id"))  # cmd_id for InvokeCommand
        invoke_cmd_id = claripy.BVV(InvokeCommandIds.FWRITE, 32).append_annotation(
            UserInput("invoke_cmd_id"))  # cmd_id for FREAD in InvokeCommand

        param0_a = state.globals['current_object_handle_ptr'].append_annotation(UserInput(
            "param0_a_fwrite_object_handle"))  # needs to be set to the memory, where the file was opened with f_open
        param0_b = claripy.BVV(0x0, 32).append_annotation(UserInput("param0_b_fwrite"))
        param0_type = claripy.BVV(TEECParamType.TEEC_VALUE_INPUT, 16).append_annotation(UserInput("param0_type_fwrite"))

        param1_a = claripy.BVV(b'Ich schreib was ich will!', 0x19 * 8).append_annotation(
            UserInput("param1_a_fwrite_inbuf"))  # needs to be set to the memory, where the file was opened with f_open
        param1_b = claripy.BVV(0x19, 32).append_annotation(UserInput("param1_b_fwrite_insize"))
        param1_type = claripy.BVV(TEECParamType.TEEC_MEMREF_TEMP_INPUT, 16).append_annotation(
            UserInput("param1_type_fwrite"))

        param0 = TCParam(param0_type, param0_a, param0_b)
        param1 = TCParam(param1_type, param1_a, param1_b)
        param2 = cls.create_empty_param()
        param3 = TCParam(TEECParamType.TEEC_NONE, None, None)

        params = TCParams(param0, param1, param2, param3)
        param_types = claripy.ZeroExt(16, params.get_param_type())
        cls.prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)

    @classmethod
    def fseek(cls, state):
        """ 4th Lifecycle: TA_InvokeCommandEntryPoint (FSEEK) """

        lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.INVOKE_COMMAND, 32).append_annotation(
            UserInput("lifecycle_cmd_id"))  # cmd_id for InvokeCommand
        invoke_cmd_id = claripy.BVV(InvokeCommandIds.FSEEK, 32).append_annotation(
            UserInput("invoke_cmd_id"))  # cmd_id for FREAD in InvokeCommand

        param0_a = state.globals['current_object_handle_ptr'].append_annotation(UserInput(
            "param0_a_fseek_obj_handle"))  # needs to be set to the memory, where the file was opened with f_open
        param0_b = claripy.BVV(0x0, 32).append_annotation(UserInput("param0_b_fseek_offset"))
        param0_type = claripy.BVV(TEECParamType.TEEC_VALUE_INPUT, 16).append_annotation(UserInput("param0_type_fseek"))

        param1_a = claripy.BVV(TeeWhence.TEE_DATA_SEEK_SET, 32).append_annotation(
            UserInput("param1_a_fseek_whence"))  # needs to be set to the memory, where the file was opened with f_open
        param1_b = claripy.BVV(0x0, 32).append_annotation(UserInput("param1_b_fseek"))
        param1_type = claripy.BVV(TEECParamType.TEEC_VALUE_INPUT, 16).append_annotation(
            UserInput("param1_type_fseek"))

        param0 = TCParam(param0_type, param0_a, param0_b)
        param1 = TCParam(param1_type, param1_a, param1_b)
        param2 = cls.create_empty_param()
        param3 = TCParam(TEECParamType.TEEC_NONE, None, None)

        params = TCParams(param0, param1, param2, param3)
        param_types = claripy.ZeroExt(16, params.get_param_type())
        cls.prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)

    @classmethod
    def fread(cls, state):
        """ 5th Lifecycle: TA_InvokeCommandEntryPoint (FREAD) """

        lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.INVOKE_COMMAND, 32).append_annotation(
            UserInput("lifecycle_cmd_id"))  # cmd_id for InvokeCommand
        invoke_cmd_id = claripy.BVV(InvokeCommandIds.FREAD, 32).append_annotation(
            UserInput("invoke_cmd_id"))  # cmd_id for FREAD in InvokeCommand

        param0_a = state.globals['current_object_handle_ptr'].append_annotation(
            UserInput("param0_a_fread"))  # needs to be set to the memory, where the file was opened with f_open
        param0_b = claripy.BVV(0x0, 32).append_annotation(UserInput("param0_b_fread"))
        param0_type = claripy.BVV(TEECParamType.TEEC_VALUE_INPUT, 16).append_annotation(UserInput("param0_type_fread"))

        param1_a = claripy.BVV(0x0, 32).append_annotation(
            UserInput("param1_a_fread_outbuf"))  # needs to be set to the memory, where the file was opened with f_open
        param1_b = claripy.BVV(0xf, 32).append_annotation(UserInput("param1_b_fread_outsize"))
        param1_type = claripy.BVV(TEECParamType.TEEC_MEMREF_TEMP_OUTPUT, 16).append_annotation(
            UserInput("param1_type_fread"))

        param0 = TCParam(param0_type, param0_a, param0_b)
        param1 = TCParam(param1_type, param1_a, param1_b)
        param2 = cls.create_empty_param()
        param3 = TCParam(TEECParamType.TEEC_NONE, None, None)

        params = TCParams(param0, param1, param2, param3)
        param_types = claripy.ZeroExt(16, params.get_param_type())
        cls.prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)

    @classmethod
    def fclose(cls, state):
        """ 6th Lifecycle: TA_InvokeCommandEntryPoint (FCLOSE) """
        lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.INVOKE_COMMAND, 32).append_annotation(
            UserInput("lifecycle_cmd_id"))  # cmd_id for InvokeCommand
        invoke_cmd_id = claripy.BVV(InvokeCommandIds.FCLOSE, 32).append_annotation(
            UserInput("invoke_cmd_id"))  # cmd_id for FCLOSE in InvokeCommand
        param0_a = state.globals['current_object_handle_ptr'].append_annotation(
            UserInput("param0_a_fclose"))  # needs to be set to the memory, where the file was opened with f_open
        param0_b = claripy.BVV(0x0, 32).append_annotation(UserInput("param0_b_fclose"))
        param0_type = claripy.BVV(TEECParamType.TEEC_VALUE_INPUT, 16).append_annotation(UserInput("param0_type_fclose"))

        param0 = TCParam(param0_type, param0_a, param0_b)
        param1 = TCParam(TEECParamType.TEEC_NONE, None, None)
        param2 = TCParam(TEECParamType.TEEC_NONE, None, None)
        param3 = TCParam(TEECParamType.TEEC_NONE, None, None)

        params = TCParams(param0, param1, param2, param3)
        param_types = claripy.ZeroExt(16, params.get_param_type())
        cls.prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)

    @classmethod
    def close_session(cls, state):
        """ 7th Lifecylce: TA_CloseSessionEntryPoint """
        lifecylce_cmd_id = claripy.BVV(LifecycleCommandIds.CLOSE_SESSION, 32).append_annotation(
            UserInput("lifecycle_cmd_id"))  # cmd_id for CloseSession

        param0 = TCParam(TEECParamType.TEEC_NONE, None, None)
        param1 = TCParam(TEECParamType.TEEC_NONE, None, None)
        param2 = TCParam(TEECParamType.TEEC_NONE, None, None)
        param3 = TCParam(TEECParamType.TEEC_NONE, None, None)

        params = TCParams(param0, param1, param2, param3)
        invoke_cmd_id = 0
        param_types = claripy.ZeroExt(16, params.get_param_type())
        cls.prepare_msg_recv_return(state, lifecylce_cmd_id, invoke_cmd_id, param_types, params)
