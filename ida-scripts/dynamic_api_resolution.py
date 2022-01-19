# used to resolve any dynamic API calls through a shared decryption function, and populate function parameters to any global "IAT" offsets statically

# how to use
# 1. find the start of the decryption function. the xrefs to this function will be used to find the ciphertext input and assign it to any plaintext outputs (if they are global vars)
# 2. replicate/lift the decryption routine
# 3. statically look for the parameters passed into the decryption routine
# 4. import into IDA and run

# CAVEATS
# 1. ciphertext is embedded within binary
# 2. decryption routine can be replicated without runtime-level factors

import idc
import idaapi
import idautils

dec_func = None # addr to decryption function

def get_tinfo_of(api_name):
    """
    retrieves type information of API name.
    Used to apply to renamed imports in IDA, to provide function parameter annotations
    """
    sym = idaapi.til_symbol_t()
    sym.til = idaapi.cvar.idati
    sym.name = api_name
    tinfo = idaapi.tinfo_t()

    named_type = idaapi.get_named_type(sym.til, sym.name, 0)

    if named_type == None:
        return tinfo, False
    
    tinfo.deserialize(sym.til, named_type[1], named_type[2])

    return tinfo, True


def decryption_routine(ciphertext):
    # write dec routine here

    pass


def get_ciphertext(func_call):
    """
    start tracing backwards from the decryption function call and look for where the ciphertext is passed
    """

    curr_addr = func_call

    while(True):
        if idc.print_operand(curr_addr, 0) == "rdx":
            ciphertext_offset = idc.get_operand_value(curr_addr, 1)

            # read ciphertext data here and return

        curr_addr = idc.prev_head(curr_addr)
    

def set_api_type(func_call, api_name):
    """
    apply function information from WinAPI to newly created & resolved API in IDA
    used to provide function parameter annotations
    """
    curr_addr = func_call

    while(True):
        # look for an assignment of the return value in rax to the first global offset
        # change accordingly with behaviour seen in code
        if idc.print_operand(curr_addr, 1) == "rax" and idc.print_insn_mnem(curr_addr) == "mov":
            api_name_offset = idc.get_operand_value(curr_addr, 0)
            api_tinfo = get_tinfo_of(api_name)

            if api_tinfo[1]:
                api_tinfo[0].create_ptr(api_tinfo[0])
                idaapi.apply_tinfo(api_name_offset, api_tinfo[0], idaapi.TINFO_DEFINITE)
            
            idc.set_name(api_name_offset, api_name, 0x800)


for xref in idautils.XrefsTo(dec_func):
    ciphertext = None

    if ciphertext:
        set_api_type(xref.frm, decryption_routine(ciphertext))
