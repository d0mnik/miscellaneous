from dataclasses import dataclass
from binaryninja import (
    Activity,
    Function,
    HighLevelILFunction,
    MediumLevelILOperation,
    Variable,
    HighLevelILBasicBlock,
    BranchType,
    HighLevelILIf,
    HighLevelILCmpE,
    HighlightStandardColor,
    HighLevelILInstruction,
    HighLevelILAssign,
    HighLevelILSub,
    HighLevelILVarInit,
    HighLevelILConst,
    Workflow,
)
from binaryninja.enums import FunctionUpdateType
from binaryninja.highlevelil import HighLevelILVar
from binaryninja.log import *

COLOR_OBB = HighlightStandardColor.GreenHighlightColor
COLOR_CF = HighlightStandardColor.RedHighlightColor
COLOR_UNLABELLED = HighlightStandardColor.NoHighlightColor


@dataclass
class FunctionInfo:
    function: Function
    state_var: Variable
    state_var_deps: list
    mappings: dict
    obbs: dict
    bb_mappings: dict
    patches: dict
    completed: bool = False


patches: dict[int, FunctionInfo] = {}


# the following code was taken from https://github.com/mrphrazer/obfuscation_detection/blob/main/obfuscation_detection/helpers.py
def calc_flattening_score(function):
    score = 0.0
    # 1: walk over all basic blocks
    for block in function.basic_blocks:
        # 2: get all blocks that are dominated by the current block
        dominated = get_dominated_by(block)
        # 3: check for a back edge
        if not any((edge.source in dominated for edge in block.incoming_edges)):
            continue
        # 4: calculate relation of dominated blocks to the blocks in the graph
        score = max(score, len(dominated) / len(function.basic_blocks))
    return score


def get_dominated_by(dominator):
    # 1: initialize worklist
    result = set()
    # add to result
    worklist = [dominator]
    # 2: perform a depth-first search on the dominator tree
    while worklist:
        # get next block
        block = worklist.pop(0)
        result.add(block)
        # add children from dominator tree to worklist
        for child in block.dominator_tree_children:
            worklist.append(child)
    return result


# end of code from mrphrazer


def is_const_or_derivable(hlil_func: HighLevelILFunction, var: Variable):
    results = hlil_func.get_var_definitions(var)
    if len(results) == 0:
        return False
    for result in results:
        if isinstance(result, (HighLevelILConst, HighLevelILVarInit)):
            continue
        # check is operand is const
        elif isinstance(result, HighLevelILAssign):
            if isinstance(result.src, HighLevelILConst):
                continue
            elif isinstance(result.src, HighLevelILVar) and not is_const_or_derivable(
                hlil_func, result.src.var
            ):
                return False
    return True


def get_most_assigned_var(hlil_func: HighLevelILFunction):
    defines = [hlil_func.get_var_definitions(var) for var in hlil_func.vars]
    most_used = max(defines, key=len)
    return most_used[0].vars_written[0]


def get_var_dependencies(hlil_func: HighLevelILFunction, var: Variable):
    defines = hlil_func.get_var_definitions(var)
    assigns = list(filter(lambda x: len(x.vars_read) != 0, defines))
    deps = []
    for assign in assigns:
        for v in assign.vars_read:
            if v not in deps:
                deps.append(v)
    return deps


def is_const(hlil_func: HighLevelILFunction, var: Variable):
    results = hlil_func.get_var_definitions(var)
    return len(results) == 1 and isinstance(
        results[0], (HighLevelILConst, HighLevelILVarInit)
    )


def can_be_derived(hlil_func: HighLevelILFunction, var: Variable):
    deps = get_var_dependencies(hlil_func, var)
    if len(deps) == 0:
        return is_const_or_derivable(hlil_func, var)
    results = [can_be_derived(hlil_func, d) for d in deps]
    return all(results)


def get_const_mappings(hlil_func: HighLevelILFunction):
    mappings = {}
    for var in hlil_func.vars:
        if is_const(hlil_func, var):
            # get const value
            init = hlil_func.get_var_definitions(var)[0]
            mappings[var] = init.src.value.value
    return mappings


def get_unconditional_branch_block(bb: HighLevelILBasicBlock):
    for block in bb.incoming_edges:
        if block.type == BranchType.UnconditionalBranch:
            return block


def get_cmp_eq_value(
    inst: HighLevelILInstruction,
    bb_mappings: dict[int, HighLevelILBasicBlock],
    obbs: list[HighLevelILBasicBlock],
):
    if isinstance(inst, HighLevelILCmpE):
        obbs[inst.instr.true.address] = inst.operands[1].value.value
        inst.function.source_function.set_comment_at(
            inst.instr.true.address, hex(obbs[inst.instr.true.address])
        )
        basic_block = (
            inst.il_basic_block.outgoing_edges[0].target
            if inst.il_basic_block.outgoing_edges[0].type == BranchType.TrueBranch
            else inst.il_basic_block.outgoing_edges[1].target
        )
        basic_block.highlight = COLOR_OBB
        bb_mappings[inst.instr.true.address] = basic_block
        return True  # stop traversal
    return False


def get_state_value(insn: HighLevelILInstruction, mappings: dict[Variable, int]):
    rhs = insn.src
    if isinstance(rhs, HighLevelILSub):
        val = -abs(rhs.operands[1].value.value)
    elif isinstance(rhs, HighLevelILConst):
        return rhs.value.value
    else:
        val = rhs.operands[1].value.value
    deps = insn.vars_read
    assert len(deps) == 1
    return (mappings[deps[0]] + val) & 0xFFFFFFFF


def get_idx_from_state(
    state, bb_mappings: dict[int, HighLevelILBasicBlock], obbs: dict[int, int]
):
    for k, v in obbs.items():
        if v == state:
            if bb_mappings[k].il_function[bb_mappings[k].start].medium_level_il is None:
                # take block after
                return (
                    bb_mappings[k]
                    .il_function[bb_mappings[k].post_dominators[0].start]
                    .medium_level_il.non_ssa_form.il_basic_block.start
                )
            return (
                bb_mappings[k]
                .il_function[bb_mappings[k].start]
                .medium_level_il.non_ssa_form.il_basic_block.start
            )
    raise RuntimeError(f"state {state} not found in obbs")


def get_insn_of_state_set(
    bb: HighLevelILBasicBlock, state_var: Variable
) -> HighLevelILInstruction | None:
    for idx in range(bb.instruction_count - 1, 0, -1):
        insn = bb[idx]
        if (
            isinstance(insn, (HighLevelILAssign, HighLevelILVarInit))
            and state_var in insn.vars_written
        ):
            return insn
    # block does not contain any instructions that sets state var
    return None


def add_patch(func_info: FunctionInfo, idx, target_idx):
    func_info.patches["simple"][idx] = (
        func_info.function.medium_level_il.get_basic_block_at(target_idx).start
    )


def add_junk(func_info: FunctionInfo, start, length):
    func_info.patches["junk"][start] = length


def cff_analysis(analysis_context):
    function: Function = analysis_context.function
    flattening_score = calc_flattening_score(function)
    # don't run analysis again
    if function.start in patches or flattening_score < 0.85:
        return
    func_patch = {"simple": {}, "junk": {}}

    bb_mappings = {}
    obbs = {}
    h_func: HighLevelILFunction = function.high_level_il
    state_var = get_most_assigned_var(h_func)
    log_info(f"Suspected state var: {state_var}")
    state_var_deps = get_var_dependencies(h_func, state_var)
    for d in get_var_dependencies(h_func, state_var):
        if not can_be_derived(h_func, d):
            raise RuntimeError(f"var {d} cannot be derived")
    mappings = get_const_mappings(h_func)
    for bb in h_func.basic_blocks:
        insn = bb[-1]
        # check if state var is involved in change of control flow
        if (
            isinstance(insn, HighLevelILIf)
            and set(insn.condition.vars_read).pop() == state_var
        ):
            bb.highlight = COLOR_CF
            # build OBB mapping
            for should_stop in insn.condition.traverse(
                get_cmp_eq_value, bb_mappings, obbs
            ):
                if should_stop:
                    break
    for bb in h_func.basic_blocks:
        if bb.highlight.color == COLOR_UNLABELLED:
            if (
                len(bb.incoming_edges) == 0
                or len(bb.outgoing_edges) == 0
                or (len(bb.outgoing_edges) == 2 and isinstance(bb[-1], HighLevelILIf))
            ):
                bb.highlight = COLOR_OBB
                obbs[bb[0].address] = 0
                bb_mappings[bb[0].address] = bb
            else:
                bb.highlight = COLOR_CF

    func_info = FunctionInfo(
        function, state_var, state_var_deps, mappings, obbs, bb_mappings, func_patch
    )

    # repair CFG
    for obb in obbs.keys():
        bb = bb_mappings[obb]
        last_insn: HighLevelILInstruction = bb[-1]
        instructions = list(h_func.instructions)
        if len(bb.outgoing_edges) > 1:
            # likely an if block
            # patch conditionals
            possible_state_set_insn: HighLevelILInstruction = bb[-2]
            # process true
            true_branch = bb.outgoing_edges[0].target
            insn: HighLevelILInstruction = instructions[true_branch.start]
            if len([var for var in insn.vars_written if var in state_var_deps]) == 0:
                raise RuntimeError("target var is not related to state var")
            target = get_idx_from_state(
                get_state_value(insn, mappings), bb_mappings, obbs
            )
            add_patch(
                func_info,
                insn.medium_level_il.non_ssa_form.il_basic_block[-1].instr_index,
                target,
            )
            insn.il_basic_block.highlight = HighlightStandardColor.YellowHighlightColor

            # process false
            false_branch = bb.outgoing_edges[1].target
            insn = instructions[false_branch.start]
            if (
                len([var for var in insn.vars_written if var in state_var_deps]) == 0
                and insn.vars_written[0] != state_var
            ):
                raise RuntimeError("target var is not related to state var")
            # calculate from slight above
            target = get_idx_from_state(
                get_state_value(possible_state_set_insn, mappings), bb_mappings, obbs
            )
            add_patch(
                func_info,
                insn.medium_level_il.non_ssa_form.il_basic_block[-1].instr_index,
                target,
            )
            insn.il_basic_block.highlight = HighlightStandardColor.YellowHighlightColor

        elif len(bb.outgoing_edges) == 1:
            # check last insn
            set_insn = get_insn_of_state_set(bb, func_info.state_var)
            if set_insn is None:
                continue
            # patch with direct jump
            target = get_idx_from_state(
                get_state_value(set_insn, mappings), bb_mappings, obbs
            )
            add_patch(
                func_info,
                set_insn.medium_level_il.non_ssa_form.il_basic_block[-1].instr_index,
                target,
            )

    for block in h_func.basic_blocks:
        if block.highlight.color == COLOR_CF:
            if block[0].medium_level_il is None:
                continue
            mlil_bb_start = block[0].medium_level_il.non_ssa_form.instr_index
            mlil_bb = h_func.medium_level_il.get_basic_block_at(mlil_bb_start)
            add_junk(func_info, mlil_bb.start, mlil_bb.length)
    patches[function.start] = func_info
    function.mark_updates_required(FunctionUpdateType.IncrementalAutoFunctionUpdate)


def patch_jumps(analysis_context):
    function: Function = analysis_context.function
    if function.start not in patches or patches[function.start].completed:
        return
    func_patches = patches[function.start].patches
    for patch_idx, target_idx in func_patches["simple"].items():
        print(f"[patching] patching {patch_idx} with {target_idx}")
        target_insn = function.mlil[int(patch_idx)]
        new_mlil_insn = function.mlil.expr(MediumLevelILOperation.MLIL_GOTO, target_idx)
        function.mlil.replace_expr(target_insn, new_mlil_insn)

    for start, length in func_patches["junk"].items():
        print(f"[patching] removing junk {start} - {int(start)+int(length)}")
        for i in range(int(length)):
            nop = function.mlil.expr(MediumLevelILOperation.MLIL_NOP)
            function.mlil.replace_expr(function.mlil[int(start) + i], nop)
    # set patch as completed
    patches[function.start].completed = True
    function.mlil.generate_ssa_form()


jmp_patch_workflow = Workflow().clone("CFFWorkflow")
jmp_patch_workflow.register_activity(Activity("cff_analysis", action=cff_analysis))
jmp_patch_workflow.register_activity(Activity("patch_jumps", action=patch_jumps))
jmp_patch_workflow.insert("core.function.analyzeTailCalls", ["patch_jumps"])
jmp_patch_workflow.insert("core.function.processCompletionState", ["cff_analysis"])
jmp_patch_workflow.register()
log_info(f"Registered workflow: {jmp_patch_workflow.name}")
