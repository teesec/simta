import claripy
from securestoragehooks import UserInput

class UnknownParamTypeException(Exception):
    pass


class TEECParamType:
    TEEC_NONE = 0x0
    TEEC_VALUE_INPUT = 0x01
    TEEC_VALUE_OUTPUT = 0x02
    TEEC_VALUE_INOUT = 0x03
    TEEC_MEMREF_TEMP_INPUT = 0x05
    TEEC_MEMREF_TEMP_OUTPUT = 0x06
    TEEC_MEMREF_TEMP_INOUT = 0x07

    VALUE_TYPES = [
        TEEC_VALUE_INPUT,
        TEEC_VALUE_OUTPUT,
        TEEC_VALUE_INOUT
    ]

    MEMREF_TYPES = [
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_MEMREF_TEMP_INOUT
    ]


class TypeCategories:
    NoneType = 0x0
    ValueType = 0x1
    MemrefType = 0x2


def get_param_type(param_num, val):
    assert param_num >= 0 and param_num < 4
    return (val >> (param_num * 4)) & 0xf


def is_bitvector(arg):
    if type(arg) is claripy.ast.bv.BV:
        return True
    return False


class TCParam(object):

    def __init__(self, type, a_or_buf, b_or_sz, watch=False):
        self.type = type
        self.a_or_buf = a_or_buf
        self.b_or_sz = b_or_sz
        self.watch = watch  # decide, if param should be added to symbolics-list (used to keep track of symbolic variables)

    def get_type_category(self):
        if is_bitvector(self.type) and self.type.symbolic:
            # if type of a TCParam is symbolic, we need to have a value-type, otherwise there is already a bug in the TA
            return TypeCategories.ValueType
        else:
            type = claripy.Solver().eval(self.type, 1)[0]
            if type == TEECParamType.TEEC_NONE:
                return TypeCategories.NoneType
            elif type in TEECParamType.VALUE_TYPES:
                return TypeCategories.ValueType
            elif type in TEECParamType.MEMREF_TYPES:
                return TypeCategories.MemrefType



class TCParams(list):

    NPARAMS = 4

    def __init__(self, param0, param1, param2, param3):
        self.append(param0)
        self.append(param1)
        self.append(param2)
        self.append(param3)

    def get_param_type(self):
        param_type = 0
        for p in self[::-1]:
            param_type = (param_type << 4) | p.type
        if type(param_type) is not claripy.ast.bv.BV:
            # param_type needs to be a bitvector
            param_type = claripy.BVV(param_type, 16).append_annotation(UserInput("param_type"))
        if param_type.symbolic:
            # TODO: might want to store complete param_type bitvector to symbolic variables as well
            pass
        return param_type
