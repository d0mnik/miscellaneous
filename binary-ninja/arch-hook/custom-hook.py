from typing import List, Tuple
from binaryninja import InstructionTextToken
from binaryninja.architecture import Architecture, ArchitectureHook


def _is_candidate(addr) -> bool:
    return True


class X86CallHook(ArchitectureHook):
    def get_instruction_info(self, data, addr):
        # Call the original implementation's method by calling the superclass
        result = super(X86CallHook, self).get_instruction_info(data, addr)

        ref_insn, length = super(X86CallHook, self).get_instruction_text(data, addr)
        if result and ref_insn[0].text == 'call':
            if _is_candidate(addr):
                result.length += 4

        return result

    
    def get_instruction_text(self, data: bytes, addr: int) -> Tuple[List[InstructionTextToken], int] | None:
        ref_insn, length = super().get_instruction_text(data, addr)
        if ref_insn[0].text == 'call' and _is_candidate(ref_insn[-1].value):
            length += 4 
        return ref_insn, length

# Install the hook by constructing it with the desired architecture to hook, then registering it
X86CallHook(Architecture['x86_64']).register()