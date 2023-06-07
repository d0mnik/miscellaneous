#include <iostream>

#include "binaryninjaapi.h"
#include "binaryninjacore.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"

using namespace BinaryNinja;

extern "C" {
BN_DECLARE_CORE_ABI_VERSION

void PatchPushRets(Ref<AnalysisContext> analysisContext) {
    Ref<LowLevelILFunction> function = analysisContext->GetLowLevelILFunction();

    size_t insnCount = function->GetInstructionCount();
    auto secondLastInsn = function->GetInstruction(insnCount - 2);
    auto lastInsn = function->GetInstruction(insnCount - 1);
    if (lastInsn.operation == BNLowLevelILOperation::LLIL_RET &&
        secondLastInsn.operation == BNLowLevelILOperation::LLIL_PUSH) {
        LogInfo("[PushRetPatcher] Found function with control flow redirection @ %llx", function->GetFunction()->GetStart());
        // patch with new instruction
        auto newInsn = function->Jump(secondLastInsn.operands[0]);
        Ref<BinaryView> bv = function->GetFunction()->GetView();
        function->ReplaceExpr(secondLastInsn.exprIndex, newInsn);
        function->ReplaceExpr(lastInsn.exprIndex, function->Nop());
        LogInfo("Patched indirect jump @ %llx", secondLastInsn.address);
    }
    function->GenerateSSAForm();
}

// run this after MLIL is generated and optimisation has happened
// would be able to tell if jump destination is calculated to be a static address
// apply function if found to be a valid address
void createFunc(Ref<AnalysisContext> analysisContext){
    Ref<MediumLevelILFunction> function = analysisContext->GetMediumLevelILFunction();

    size_t insnCount = function->GetInstructionCount();
    auto lastInsn = function->GetInstruction(insnCount - 1);
    if(lastInsn.operation != BNMediumLevelILOperation::MLIL_JUMP){
        return;
    }
    Ref<BinaryView> bv = function->GetFunction()->GetView();
    if (lastInsn.GetRawOperandAsExpr(0).GetType()->IsPointer()){
        uint64_t address = lastInsn.GetRawOperandAsExpr(0).GetConstant();
        LogInfo("[PushRetPatcher] Creating function @ %llx", address);
        bv->CreateUserFunction(function->GetFunction()->GetPlatform(), address);
    }
}

BINARYNINJAPLUGIN bool CorePluginInit() {
    Ref<Workflow> controlFlowRedirectionWorkflow =
        Workflow::Instance()->Clone("PatchControlFlowRedirects");
    controlFlowRedirectionWorkflow->RegisterActivity(
        new Activity("extension.patchPushRets", &PatchPushRets));
    controlFlowRedirectionWorkflow->RegisterActivity(
        new Activity("extension.createPushRetSymbol", &createFunc));
    controlFlowRedirectionWorkflow->Insert("core.function.generateMediumLevelIL",
                                  "extension.patchPushRets");
    controlFlowRedirectionWorkflow->Insert("core.function.analyzeMLILTypeReferences",
                                  "extension.createPushRetSymbol");
    Workflow::RegisterWorkflow(controlFlowRedirectionWorkflow,
                               R"#({
			"title" : "Simple control flow redirection patcher",
			"description" : "Detects and patches simple control flow redirections via push ret sequences to jumps at the IL level via Workflows!",
			"capabilities" : []
			})#");

    return true;
}
}