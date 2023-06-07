import angr
import claripy
import logging

# logging.getLogger('angr').setLevel('DEBUG')

p = angr.Project('./challenge', auto_load_libs=False)

stdin_chars = [claripy.BVS("stdin_%d" % i, 8) for i in range(25)]
buf = claripy.Concat(*stdin_chars)

state = p.factory.entry_state(args=['./challenge',buf], add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY, angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,})
for k in stdin_chars:
    state.solver.add(k <= 0x7F)
    state.solver.add(k > 0x20)

sm = p.factory.simgr(state)


@p.hook(0x4013ce)
def skip1(state):
    state.regs.ip = 0x40141d

@p.hook(0x401452)
def skip2(state):
    state.regs.ip = 0x401483

while True:
    sm.step()
    found_list = [active for active in sm.active if active.addr == 0x40149b]
    if len(found_list) > 0:
        print(found_list[0].solver.eval(buf, cast_to=bytes))
        break
