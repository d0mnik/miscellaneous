import idaapi
import ida_funcs


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


def set_api_type(ea, api_name):
    """
    apply function information from WinAPI to newly created & resolved API in IDA
    used to provide function parameter annotations
    """
    # create func at address
    ida_funcs.add_func(ea)
    api_tinfo = get_tinfo_of(api_name)
    if api_tinfo[1]:
        api_tinfo[0].create_ptr(api_tinfo[0])
        idaapi.apply_tinfo(ea, api_tinfo[0], idaapi.TINFO_DEFINITE)
        idaapi.set_name(ea, api_name, idaapi.SN_FORCE)
        
