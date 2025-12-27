#ifndef LLVM_BOGUS_H
#define LLVM_BOGUS_H

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "vector"

struct BogusFlow : public llvm::PassInfoMixin<BogusFlow> {
  llvm::PreservedAnalyses run(llvm::Module &F,
                              llvm::ModuleAnalysisManager &);
  bool runOnFunction(llvm::Function &);
  llvm::Value* randomOperations(llvm::BasicBlock* block, llvm::Function& F, int& controlVal, int iterations);
  void genFakeFlow(llvm::BasicBlock* block, llvm::Function& F,std::vector<llvm::BasicBlock*>& allBB,int numBlocks);
};

#endif
