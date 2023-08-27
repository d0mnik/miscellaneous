import ida_struct
import ida_typeinf

def add_struct(name):
    '''adds a struct into the idb, retiurns a pointer to the struct type info'''

    ida_struct.add_struc(0, name, 0)
    struct_id = ida_struct.get_struc_id(name)
    return ida_struct.get_struc(struct_id)


def add_struct_member(struct_ptr, member_name, member_type, offset, member_size):
	'''add members into struct along with type info'''

    tinfo = ida_typeinf.tinfo_t()
    ret = ida_typeinf.parse_decl(tinfo, None, member_type, 1)
    if ret is None:
        print('failed to parse type')
        return
    ida_struct.add_struc_member(struct_ptr, member_name, offset, 0, None, member_size)
    member_ptr = ida_struct.get_member_by_name(struct_ptr, member_name)
    ida_struct.set_member_tinfo(struct_ptr, member_ptr, 0, tinfo, member_ptr.flag)
    
