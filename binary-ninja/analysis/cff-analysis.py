from binaryninja import BinaryView, HighLevelILFunction, Variable, HighLevelILBasicBlock, BranchType, HighLevelILIf, HighLevelILCmpE, HighlightStandardColor, HighLevelILInstruction, HighLevelILAssign, HighLevelILSub, HighLevelILVarInit, HighLevelILConst
from binaryninja.log import *
from pathlib import Path
import json

bv: BinaryView

COLOR_OBB = HighlightStandardColor.GreenHighlightColor
COLOR_CF = HighlightStandardColor.RedHighlightColor
COLOR_UNLABELLED = HighlightStandardColor.NoHighlightColor

def is_const(hlil_func: HighLevelILFunction, var: Variable):
    results = hlil_func.get_var_definitions(var)
    return len(results) == 1 and isinstance(results[0], (HighLevelILConst, HighLevelILVarInit))


def get_most_assigned_var(hlil_func: HighLevelILFunction):
    defines = [hlil_func.get_var_definitions(var) for var in hlil_func.vars]
    most_used = max(defines, key=len)
    return most_used[0].vars_written[0]


def get_var_dependencies(hlil_func: HighLevelILFunction, var: Variable):
    defines = hlil_func.get_var_definitions(var)
    assigns = list(filter(lambda x:len(x.vars_read) != 0, defines))
    deps = []
    for assign in assigns:
        for v in assign.vars_read:
            if v not in deps:
                deps.append(v)
    return deps


def can_be_derived(hlil_func: HighLevelILFunction, var: Variable):
    deps = get_var_dependencies(hlil_func, var)
    if len(deps) == 0:
        return is_const(h_func,var)
    results = [can_be_derived(h_func,d) for d in deps]
    return all(results)


def get_const_mappings(hlil_func: HighLevelILFunction):
    mappings = {}
    for var in hlil_func.vars:
        if is_const(hlil_func,var):
            # get const value
            init = hlil_func.get_var_definitions(var)[0]
            mappings[var] = init.src.value.value 
    return mappings


def get_unconditional_branch_block(bb: HighLevelILBasicBlock):
    for block in bb.incoming_edges:
        if block.type == BranchType.UnconditionalBranch:
            return block


def get_cmp_eq_value(operand_name, operand, operand_type, parent):
    if isinstance(operand, HighLevelILCmpE):
        global obbs, bb_mappings
        obbs[operand.instr.true.address] = operand.operands[1].value.value
        operand.function.source_function.set_comment_at(operand.instr.true.address, hex(obbs[operand.instr.true.address]))
        basic_block = operand.il_basic_block.outgoing_edges[0].target if operand.il_basic_block.outgoing_edges[0].type == BranchType.TrueBranch else operand.il_basic_block.outgoing_edges[1].target
        basic_block.highlight = COLOR_OBB
        bb_mappings[operand.instr.true.address] = basic_block
        return False # stop traversal
    return True


def get_state_value(insn: HighLevelILInstruction):
    rhs = insn.src
    if isinstance(rhs, HighLevelILSub):
        val = -abs(rhs.operands[1].value.value)
    elif isinstance(rhs, HighLevelILConst):
        return rhs.value.value
    else:
        val = rhs.operands[1].value.value
    deps = insn.vars_read
    assert len(deps) == 1
    return (mappings[deps[0]] + val)&0xffffffff


def get_idx_from_state(state):
    for k,v in obbs.items():
        if v == state:
            if bb_mappings[k].il_function[bb_mappings[k].start].medium_level_il is None:
                # take block after
                return bb_mappings[k].il_function[bb_mappings[k].post_dominators[0].start].medium_level_il.non_ssa_form.instr_index
            return bb_mappings[k].il_function[bb_mappings[k].start].medium_level_il.non_ssa_form.instr_index
            

def add_patch(fn_start, idx, target_idx):
    patches[fn_start]['simple'][idx] = bv.get_function_at(fn_start).medium_level_il.get_basic_block_at(target_idx).start


def add_complex_patch(fn_start, idx, conditional_idx, true_idx, false_idx):
    patches[fn_start]['ifs'][idx] = (conditional_idx, true_idx, false_idx)


def add_special_patch(fn_start, idx, true_idx, false_idx):
    patches[fn_start]['special'][idx] = (true_idx, false_idx)


def add_junk(fn_start, start, length):
    patches[fn_start]['junk'][start] = length


path = Path('REDACTED')

fn_start = 0x401140
patches: dict = {}
patches[fn_start] = {'simple': {}, 'ifs': {}, 'special': {}, 'junk': {}}

bv.begin_undo_actions()
h_func: HighLevelILFunction = bv.get_function_at(0x401140).high_level_il
state_var = get_most_assigned_var(h_func)
log_info(f"Suspected state var: {state_var}")
state_var_writes = h_func.get_var_definitions(state_var)
state_var_deps = get_var_dependencies(h_func, state_var)
for d in get_var_dependencies(h_func, state_var):
    if not can_be_derived(h_func, d):
        raise RuntimeError(f"var {d} cannot be derived")
mappings = get_const_mappings(h_func)
obbs = {}
bb_mappings = {}
for bb in h_func.basic_blocks:
    if len(bb) != 1:
        continue
    insn = bb.get_disassembly_text()[0].il_instruction
    # check if state var is involved in change of control flow
    if isinstance(insn, HighLevelILIf) and insn.vars_read[0] == state_var:
        bb.highlight = COLOR_CF
        # build OBB mapping
        insn.condition.visit(get_cmp_eq_value)

for bb in h_func.basic_blocks:
    if bb.highlight.color == COLOR_UNLABELLED:
        if len(bb.incoming_edges) == 0 or len(bb.outgoing_edges) == 0:
            bb.highlight = COLOR_OBB
            obbs[bb.disassembly_text[0].address] = 0
            bb_mappings[bb.disassembly_text[0].address] = bb
        else:
            bb.highlight = COLOR_CF

print(obbs)

# repair CFG
for obb in obbs.keys():
    bb = bb_mappings[obb]
    last_insn: HighLevelILInstruction = bb.disassembly_text[-1].il_instruction
    instructions = list(h_func.instructions)
    if len(bb.outgoing_edges) > 1:
        # likely an if block
        # patch conditionals
        possible_state_set_insn: HighLevelILInstruction  = bb.disassembly_text[-2].il_instruction
        # process true
        true_branch = bb.outgoing_edges[0].target
        insn: HighLevelILInstruction = instructions[true_branch.start]
        if len([var for var in insn.vars_written if var in state_var_deps]) == 0:
            raise RuntimeError("target var is not related to state var")
        target = get_idx_from_state(get_state_value(insn))
        add_patch(insn.function.root.address, insn.medium_level_il.non_ssa_form.instr_index, target)
        insn.il_basic_block.highlight = HighlightStandardColor.YellowHighlightColor

        # process false
        false_branch = bb.outgoing_edges[1].target
        insn = instructions[false_branch.start]
        if len([var for var in insn.vars_written if var in state_var_deps]) == 0 and insn.vars_written[0] != state_var:
            raise RuntimeError("target var is not related to state var")
        # calculate from slight above
        target = get_idx_from_state(get_state_value(possible_state_set_insn))
        add_patch(insn.function.root.address, insn.medium_level_il.non_ssa_form.instr_index, target)

        insn.il_basic_block.highlight = HighlightStandardColor.YellowHighlightColor
    elif len(bb.outgoing_edges) == 1:
        # check last insn
        if not isinstance(last_insn, (HighLevelILAssign, HighLevelILVarInit)):
            continue
        if state_var not in last_insn.vars_written:
            continue
        # patch with direct jump
        target = get_idx_from_state(get_state_value(last_insn))
        add_patch(last_insn.function.root.address, last_insn.medium_level_il.non_ssa_form.instr_index, target)

for block in h_func.basic_blocks:
    if block.highlight.color == COLOR_CF:
        if block.il_function[block.start].medium_level_il is None:
            continue
        mlil_bb_start = block.il_function[block.start].medium_level_il.non_ssa_form.instr_index
        mlil_bb = h_func.medium_level_il.get_basic_block_at(mlil_bb_start)
        add_junk(fn_start, mlil_bb.start, mlil_bb.length)

bv.commit_undo_actions()

with open(path/'patches.json', 'w') as outfile:
    json.dump(patches, outfile)

