import json
from pathlib import Path
from binaryninja import (
    MediumLevelILOperation,
    Workflow,
    Activity,
    Function,
    log_info
)

path = Path('redacted')

def patch_jumps(analysis_context):
    with open(path/'patches.json','r') as f:
        patches = json.load(f)

    function: Function = analysis_context.function
    func_addr = str(function.start)
    if func_addr not in patches.keys():
        return
    print('found function to patch')
    for patch_idx, target_idx in patches[func_addr]['simple'].items():
        print(f'[patching] patching {patch_idx} with {target_idx}')
        target_insn = function.mlil[int(patch_idx)]
        new_mlil_insn = function.mlil.expr(MediumLevelILOperation.MLIL_GOTO, target_idx)
        function.mlil.replace_expr(target_insn, new_mlil_insn)

    for patch_idx, args in patches[func_addr]['ifs'].items():
        print(f'[patching] patching {patch_idx} with {args}')
        target_insn = function.mlil[int(patch_idx)]
        new_mlil_insn = function.mlil.expr(MediumLevelILOperation.MLIL_IF, args[0], args[1], args[2])
        function.mlil.replace_expr(target_insn, new_mlil_insn)

    for patch_idx, args in patches[func_addr]['special'].items():
        print(f'[patching] special patching {patch_idx} with {args}')
        target_insn = function.mlil[int(patch_idx)]
        mlil_bb = function.mlil[int(patch_idx)].il_basic_block
        var_id = None
        print(f'[workflow] {mlil_bb.start} - {mlil_bb.end-1}')
        for i in range(mlil_bb.start, mlil_bb.end-1):
            print(f'[workflow] operation: {function.mlil[i].operation}')
            if function.mlil[i].operation == MediumLevelILOperation.MLIL_CALL:
                var_id = function.mlil[i+1].operands[0].identifier
                break
        if var_id is None:
            raise RuntimeError('Unable to find variable id')
    
        # craft constant
        const = function.mlil.expr(MediumLevelILOperation.MLIL_CONST, 0)
        # craft variable
        var = function.mlil.expr(MediumLevelILOperation.MLIL_VAR, var_id)
        # craft CMP_NE
        cmp = function.mlil.expr(MediumLevelILOperation.MLIL_CMP_SLT, var, const)
        final = function.mlil.expr(MediumLevelILOperation.MLIL_IF, cmp, args[0], args[1])
        function.mlil.replace_expr(target_insn, final)

    for start, length in patches[func_addr]['junk'].items():
        print(f'[patching] removing junk {start} - {int(start)+int(length)}')
        for i in range(int(length)):
            nop = function.mlil.expr(MediumLevelILOperation.MLIL_NOP)
            function.mlil.replace_expr(function.mlil[int(start) + i], nop)
    
    function.mlil.generate_ssa_form()
    

jmp_patch_workflow = Workflow().clone("CFFWorkflow")
jmp_patch_workflow.register_activity(
    Activity("custom_jmp", action=patch_jumps))
jmp_patch_workflow.insert('core.function.analyzeTailCalls', ['custom_jmp'])
jmp_patch_workflow.register()
log_info(f'Registered workflow: {jmp_patch_workflow.name}')
