from capstone import Cs
from qiling import Qiling
from qiling.const import QL_INTERCEPT, QL_VERBOSE
import re

target_reg = None
idx = None
flag = {}

# https://github.com/qilingframework/qiling/issues/1201
def bypass_isa_check(ql: Qiling) -> None:
    print("by_pass_isa_check():")
    ql.arch.regs.rip += 0x15
    pass


def bypass_ptrace(ql: Qiling, *kwargs):
    pass


def simple_diassembler(ql: Qiling, address: int, size: int, md: Cs) -> None:
    global flag
    buf = ql.mem.read(address, size)
    global target_reg
    global idx
    insn = next(md.disasm(buf, address))
    ql.log.debug(f':: {insn.address:#x} : {insn.mnemonic:24s} {insn.op_str}')
    if 'byte ptr' in insn.op_str:
        # hook movzx with ptr
        print('found')
        r = re.findall('\[(.*)\]', insn.op_str)[0].split(' + ')[1]
        # get dest reg
        target_reg = insn.op_str.split(',')[0]
        # get idx of check
        idx = ql.arch.regs.read(r)
        return
        
    elif insn.mnemonic == 'sub' and target_reg is not None:
        if target_reg not in insn.op_str:
            return
        # noticed a pattern of a sub with the mov above
        op = insn.op_str.split(',')[0]
        val = ql.arch.regs.read(op.upper())
        target_reg = None
        if val > 128:
            return
        flag[idx] = chr(val)


def mmap_exit(ql:Qiling, *kwargs):
    retval = kwargs[-1]
    size = kwargs[1] 
    if size == 0x1000:
        print(f'found addr to hook: {retval:x}')
        ql.hook_code(simple_diassembler, begin=retval, end=retval+size, user_data=ql.arch.disassembler)
        

ql = Qiling([r'<REDACTED>', 'abcdef'], r'qiling/examples/rootfs/x8664_linux-test', verbose=QL_VERBOSE.DEBUG)

ld_so_base = 0x7ffff7dd5000
ql.hook_address(bypass_isa_check, ld_so_base+0x2389f) # ld.so base + jz offset

ql.os.set_syscall('ptrace', bypass_ptrace, QL_INTERCEPT.CALL)
ql.os.set_syscall('mmap', mmap_exit, QL_INTERCEPT.EXIT)
ql.run()

print(flag)
for i in range(len(flag.keys())):
    print(flag[i],end='')
