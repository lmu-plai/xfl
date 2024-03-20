
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, Tristan Benoit, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

import numpy as np
import re

EXPR_LIST = [
    "Iex_Binop",
    "Iex_CCall",
    "Iex_Const",
    "Iex_Get",
    "Iex_GetI",
    "Iex_ITE",
    "Iex_Load",
    "Iex_Qop",
    "Iex_RdTmp",
    "Iex_Triop"
    "Iex_Unop",
]

OPER_LIST = [
    "Iop_128HIto64",
    "Iop_128to64",
    "Iop_16HLto32",
    "Iop_16Sto32",
    "Iop_16Sto64",
    "Iop_16Uto32",
    "Iop_16Uto64",
    "Iop_1Uto64",
    "Iop_1Uto8",
    "Iop_32HLto64",
    "Iop_32Sto64",
    "Iop_32Uto64",
    "Iop_32UtoV128",
    "Iop_32to16",
    "Iop_32to8",
    "Iop_64HIto32",
    "Iop_64HLto128",
    "Iop_64HLtoV128",
    "Iop_64UtoV128",
    "Iop_64to1",
    "Iop_64to16",
    "Iop_64to32",
    "Iop_64to8",
    "Iop_64x4toV256",
    "Iop_8HLto16",
    "Iop_8Sto32",
    "Iop_8Sto64",
    "Iop_8Uto32",
    "Iop_8Uto64",
    "Iop_Add16",
    "Iop_Add32",
    "Iop_Add64",
    "Iop_Add64F0x2",
    "Iop_Add64Fx2",
    "Iop_Add8",
    "Iop_AddF64",
    "Iop_And16",
    "Iop_And32",
    "Iop_And64",
    "Iop_And8",
    "Iop_AndV128",
    "Iop_AndV256",
    "Iop_CasCmpNE32",
    "Iop_CasCmpNE8",
    "Iop_CmpEQ16",
    "Iop_CmpEQ32",
    "Iop_CmpEQ64",
    "Iop_CmpEQ8",
    "Iop_CmpEQ8x16",
    "Iop_CmpF64",
    "Iop_CmpLE32S",
    "Iop_CmpLE32U",
    "Iop_CmpLE64S",
    "Iop_CmpLE64U",
    "Iop_CmpLT32F0x4",
    "Iop_CmpLT32S",
    "Iop_CmpLT32U",
    "Iop_CmpLT64F0x2",
    "Iop_CmpLT64S",
    "Iop_CmpLT64U",
    "Iop_CmpNE32",
    "Iop_CmpNE64",
    "Iop_CmpNE8",
    "Iop_Div64F0x2",
    "Iop_DivF64",
    "Iop_DivModS128to64",
    "Iop_DivModS64to32",
    "Iop_DivModU128to64",
    "Iop_F32toF64",
    "Iop_F64toF32",
    "Iop_F64toI32S",
    "Iop_F64toI64S",
    "Iop_GetMSBs8x16",
    "Iop_I32StoF64",
    "Iop_I64StoF64",
    "Iop_InterleaveHI64x2",
    "Iop_InterleaveLO16x8",
    "Iop_InterleaveLO32x4",
    "Iop_InterleaveLO64x2",
    "Iop_InterleaveLO8x16",
    "Iop_Max32F0x4",
    "Iop_Min64F0x2",
    "Iop_Mul32",
    "Iop_Mul32F0x4",
    "Iop_Mul64",
    "Iop_Mul64F0x2",
    "Iop_MulF64",
    "Iop_MullS32",
    "Iop_MullS64",
    "Iop_MullU32",
    "Iop_MullU64",
    "Iop_NegF64",
    "Iop_Not32",
    "Iop_Not64",
    "Iop_Not8",
    "Iop_NotV128",
    "Iop_NotV256",
    "Iop_Or16",
    "Iop_Or32",
    "Iop_Or64",
    "Iop_Or8",
    "Iop_OrV128",
    "Iop_OrV256"
    "Iop_Perm8x8",
    "Iop_ReinterpF64asI64",
    "Iop_ReinterpI64asF64",
    "Iop_Sar32",
    "Iop_Sar64",
    "Iop_SarN8x8",
    "Iop_Shl32",
    "Iop_Shl64",
    "Iop_Shl8",
    "Iop_ShlN8x8",
    "Iop_Shr32",
    "Iop_Shr64",
    "Iop_Shr8",
    "Iop_ShrN32x2",
    "Iop_Sub32",
    "Iop_Sub64",
    "Iop_Sub64F0x2",
    "Iop_Sub64Fx2",
    "Iop_Sub64x2",
    "Iop_Sub8",
    "Iop_SubF64",
    "Iop_V128HIto64",
    "Iop_V128to64",
    "Iop_V256toV128_0",
    "Iop_V256toV128_1",
    "Iop_Xor32",
    "Iop_Xor64",
    "Iop_Xor8",
    "Iop_XorV128",
]


IST_LIST = [
    "Ist_AbiHint",
    "Ist_Dirty",
    "Ist_Exit",
    "Ist_IMark",
    "Ist_MBE",
    "Ist_Put",
    "Ist_PutI",
    "Ist_Store",
    "Ist_WrTmp"
]


#todo build graph of algorithm and compare between symbols
CAT_OPER_LIST = [
    "Iop_(.*)to(.*)", #conversion
    #"Iop_F(.*)to(.*)", #float conversion
    #"Iop_I(.*)StoF(.*)", #int to float conversion
    #"Iop_V(.*)to(.*)", #convert vector
    "Iop_Add(.*)", #add
    "Iop_And(.*)", #and
    "Iop_(Cmp|CasCmp)(.*)", #compare
    #"Iop_Cmp(.*)", #cmp
    #"Iop_CasCmp(.*)", #compare and swap
    "Iop_Div(.*)", #div
    #"Iop_DivMod(.*)", #div modulo
    "Iop_Get(M|L)SB(.*)", #Significant Bit
    "Iop_Interleave(.*)", #interleave
    "Iop_(Min|Max)(.*)", #min/max
    "Iop_Mul(.*)", #mul
    "Iop_Neg(.*)", #negate float
    "Iop_Not(.*)", #not
    "Iop_Or(.*)", #or
    "Iop_Perm(.*)", #perm
    "Iop_Reinterp(.*)as(.*)", #reinturpret
    "Iop_S(h|a)(.*)", #shift
    #"Iop_Sar(.*)", #sar
    #"Iop_Shl(.*)", #shl
    #"Iop_Shr(.*)", #shr
    "Iop_Sub(.*)", #sub
    "Iop_Xor(.*)", #xor
]

CAT_INST_LIST = [
    #"Ist_AbiHint", #???
    #"Ist_Dirty",#???
    "Ist_Exit",
    "Ist_IMark",
    "Ist_MBE", #memory barrier?
    "Ist_Put(.*)", #put
    "Ist_(Store|WrTmp)", #write
]

CAT_EXPR_LIST = [
    "Iex_Binop",
    "Iex_CCall",
    "Iex_Const",
    "Iex_Get",
    "Iex_GetI",
    "Iex_ITE",
    "Iex_Load",
    "Iex_Qop",
    "Iex_RdTmp",
    "Iex_Triop"
    "Iex_Unop",
]

#Pre-compile all regexs
CAT_EXPR_RE = []
CAT_INST_RE = []
CAT_OPER_RE = []

def __desyl_init__():
    for re_list, cat_list in [ (CAT_EXPR_RE, CAT_EXPR_LIST), (CAT_OPER_RE, CAT_OPER_LIST), (CAT_INST_RE, CAT_INST_LIST) ]:
        for cat in cat_list:
            #logger.debug("Compiling regex")
            re_list.append( re.compile( cat ) )

#builds a numpy matrix response to the vex ir 
def catagorise_vex_ir(vex_ir, cat_re_list):
    mat = np.zeros(( len(cat_re_list), ), dtype=np.uint64)
    for i in range( len(cat_re_list) ):
        mat[i] = 1 if cat_re_list[i].match( vex_ir ) else 0
    
    return mat

def catagorise_vex_expression(vex_ir):
    return catagorise_vex_ir( vex_ir.tag, CAT_EXPR_RE)

def catagorise_vex_operation(vex_ir):
    return catagorise_vex_ir( vex_ir, CAT_OPER_RE)

def catagorise_vex_statement(vex_ir):
    return catagorise_vex_ir( vex_ir.tag, CAT_INST_RE)


"""
    print("Fetching VEX'd symbols from db...")
    db_ref = Database()
    db = db_ref.client

    res = db[FROM_COL_NAME].find({ 'type': 'symtab' })
    for symb in res:
        VEX_VEC = []
        vex = symb['vex']
        #pprint.pprint( vex )
        for sum_dict, regexes in [ (vex['sum_expressions'], CAT_EXPR_RE), (vex['sum_operations'], CAT_OPER_RE), (vex['sum_statements'], CAT_INST_RE) ]:
            out_vec = np.zeros( (len(regexes)), dtype=np.int)
            #print("SUM_DICT:")
            #pprint.pprint( sum_dict )
            #print("END")

            for reg_i in range(len(regexes)):
                assert(isinstance(sum_dict, dict))
                for key, value in sum_dict.items():
                    if regexes[reg_i].match( key ):
                        out_vec[reg_i] += value

            VEX_VEC += out_vec.tolist()
            #print("OUT_VEC:")
            #pprint.pprint(out_vec)
        #print("VEX_VEC:")
        #pprint.pprint(VEX_VEC)

        new_obj = {
            "symb_id" : symb['_id'],
            "vex_vector" : VEX_VEC
        }
        db[TO_COL_NAME].insert_one(new_obj)
"""


def check_cardinality(collection_name):
    print("[+] Checking cardinality...")

    db_ref = Database()
    db = db_ref.client

    unique_vectors = {}

    res = db[collection_name].find({})
    for symb in res:
        #create string from vex vector
        vec_hash = "".join(str(i) for i in symb['vex_vector'])
        if not vec_hash in unique_vectors:
            unique_vectors[vec_hash] = 1
        else:
            unique_vectors[vec_hash] += 1


    keys = len( list( unique_vectors.keys() ) )
    avg_value = mean( list( unique_vectors.values() ) )
    #print("[+] {} unique vectors!".format( keys ) )
    #print("[+] {} average number of vectors per vector".format( avg_value ) )
                
#matrix definition
"""
    [
        Vex Size,
        nVexTempVars,
        nVexBlocks
    ]
"""

"""
#if __name__ == "__main__":
    #create_vectorised_symbols("temp_tmux", "analysis_tmux")
    #create_vectorised_symbols("symbols", "analysis")
    #check_cardinality("analysis")
"""

__desyl_init__()
