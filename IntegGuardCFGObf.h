#ifndef LLVM_INTEGGUARD_H
#define LLVM_INTEGGUARD_H

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

struct IntegGuardCFGObf : public llvm::PassInfoMixin<IntegGuardCFGObf> {
    llvm::PreservedAnalyses run(llvm::Module &M,
                                llvm::ModuleAnalysisManager &);
    bool runOnModule(llvm::Module &M);
};

#endif
