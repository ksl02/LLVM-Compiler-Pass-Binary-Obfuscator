#include "Bogus.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Utils/LowerSwitch.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

#include <iostream>
#include <random>
#include <vector>

using namespace llvm;
using std::cout, std::vector, std::endl;

#define DEBUG_TYPE "bogus-flow"
#define NUMCHOICES 17

std::random_device rd;
std::mt19937 g(rd());
std::uniform_int_distribution<int16_t> dist16(0,INT16_MAX);
std::uniform_int_distribution<int8_t> dist8(2,INT8_MAX);

static vector<GlobalVariable*> globals;

bool containsPHI(BasicBlock &B) {
    for(BasicBlock::iterator I = B.begin(), IE = B.end(); I != IE; ++I){
        if(isa<PHINode>(I))
            return true;
    }
    return false;
}

Value* ensureNot0(BasicBlock* block, llvm::Function& F, llvm::Value* value, int& control) {
    if(control == 0) {
        IRBuilder<> builder(block);
        int add = dist8(g);
        control += add;
        value = builder.CreateAdd(value,ConstantInt::get(Type::getInt32Ty(F.getContext()),add));
    }
    return value;
}

llvm::Value* ensureGT0(BasicBlock* block, llvm::Function& F, llvm::Value* value, int& control) {
    value = ensureNot0(block,F,value,control);

    if(control < 0) {
        IRBuilder<> builder(block);
        value = builder.CreateAnd(value, ConstantInt::get(Type::getInt32Ty(F.getContext()), 0x7fffffff));
        control &= 0x7fffffff;
    }

    return value;
}

GlobalVariable* createGlobal(Module &M) {
    ConstantInt *var = ConstantInt::get(Type::getInt32Ty(M.getContext()), rd());
    GlobalVariable* tmpGlobal = new GlobalVariable(
        M,
        IntegerType::getInt32Ty(M.getContext()),
        false,
        GlobalVariable::InternalLinkage,
        var,
        "");
    globals.push_back(tmpGlobal);
    return tmpGlobal;
}

GlobalVariable* getRandGlobal() {
    std::uniform_int_distribution<int> vdist(0,globals.size()-1);
    return globals.at(vdist(g));
}

void BogusFlow::genFakeFlow(BasicBlock* block, llvm::Function& F,vector<BasicBlock*>& allBB,int numLevels) {
    if(numLevels == 0) {
        std::uniform_int_distribution<int> vdist(0,allBB.size()-1);
        BranchInst::Create(allBB.at(vdist(g)),block);
        return;
    }
    int retval;
    Value* res = this->randomOperations(block,F,retval,rd()%25);
    IRBuilder<> builder(block);
    BasicBlock* leftBlock = BasicBlock::Create(F.getContext(),"left",&F);
    BasicBlock* rightBlock;
    Value* cmp;
    Value* tmpVal;
    allBB.push_back(leftBlock);
    GlobalVariable* tmp;
    numLevels--;
    int numLvlsCp = numLevels;
    switch(rd()%7) {
            case 0:
                tmp = getRandGlobal();
                builder.CreateStore(res,tmp,true);
                BranchInst::Create(leftBlock,block);
                break;
            case 1:
                tmp = getRandGlobal();
                tmpVal = builder.CreateLoad(Type::getInt32Ty(F.getContext()),tmp);
                rightBlock = BasicBlock::Create(F.getContext(),"right",&F);
                allBB.push_back(rightBlock);
                this->genFakeFlow(rightBlock,F,allBB,numLvlsCp);
                cmp = builder.CreateICmpSGT(res,tmpVal);
                builder.CreateCondBr(cmp,rightBlock,leftBlock);
                break;
            case 2:
                rightBlock = BasicBlock::Create(F.getContext(),"right",&F);
                allBB.push_back(rightBlock);
                this->genFakeFlow(rightBlock,F,allBB,numLvlsCp);
                cmp = builder.CreateICmpSGT(res,ConstantInt::get(Type::getInt32Ty(F.getContext()),rd()));
                builder.CreateCondBr(cmp,rightBlock,leftBlock);
                break;
            case 3:
                rightBlock = BasicBlock::Create(F.getContext(),"right",&F);
                allBB.push_back(rightBlock);
                this->genFakeFlow(rightBlock,F,allBB,numLvlsCp);
                cmp = builder.CreateICmpNE(res,ConstantInt::get(Type::getInt32Ty(F.getContext()),rd()));
                builder.CreateCondBr(cmp,rightBlock,leftBlock);
                break;
            case 4:
                rightBlock = BasicBlock::Create(F.getContext(),"right",&F);
                allBB.push_back(rightBlock);
                this->genFakeFlow(rightBlock,F,allBB,numLvlsCp);
                cmp = builder.CreateICmpEQ(res,ConstantInt::get(Type::getInt32Ty(F.getContext()),rd()));
                builder.CreateCondBr(cmp,rightBlock,leftBlock);
                break;
            case 5:
                rightBlock = BasicBlock::Create(F.getContext(),"right",&F);
                allBB.push_back(rightBlock);
                this->genFakeFlow(rightBlock,F,allBB,numLvlsCp);
                cmp = builder.CreateICmpNE(res,ConstantInt::get(Type::getInt32Ty(F.getContext()),0));
                builder.CreateCondBr(cmp,rightBlock,leftBlock);
                break;
            case 6:
                rightBlock = BasicBlock::Create(F.getContext(),"right",&F);
                allBB.push_back(rightBlock);
                this->genFakeFlow(rightBlock,F,allBB,numLvlsCp);
                cmp = builder.CreateICmpEQ(res,ConstantInt::get(Type::getInt32Ty(F.getContext()),0));
                builder.CreateCondBr(cmp,rightBlock,leftBlock);
                break;
            default:
                break;
        }
    this->genFakeFlow(leftBlock,F,allBB,numLevels);
}

Value* BogusFlow::randomOperations(BasicBlock* block, llvm::Function& F, int& controlVal, int iterations) {
    //x,y,z,res
    int32_t control[4] = {dist16(g),dist8(g),dist8(g),0};
    int modby;

    IRBuilder<> builder(block);
    AllocaInst* x = builder.CreateAlloca(Type::getInt32Ty(F.getContext()),0,"x");
    builder.CreateStore(ConstantInt::get(Type::getInt32Ty(F.getContext()),control[0]),x);

    AllocaInst* y = builder.CreateAlloca(Type::getInt32Ty(F.getContext()),0,"y");
    builder.CreateStore(ConstantInt::get(Type::getInt32Ty(F.getContext()),control[1]),y);

    AllocaInst* z = builder.CreateAlloca(Type::getInt32Ty(F.getContext()),0,"z");
    builder.CreateStore(ConstantInt::get(Type::getInt32Ty(F.getContext()),control[2]),z);

    Value* res = builder.CreateLoad(Type::getInt32Ty(F.getContext()),x);
    Value* ly = builder.CreateLoad(Type::getInt32Ty(F.getContext()),y);
    Value* lz = builder.CreateLoad(Type::getInt32Ty(F.getContext()),z);
    Value* randNum;
    int randNumCtrl;

    control[3] = control[0]; //set res to x
    GlobalVariable* tmp;

    for(int i = 0; i < iterations; i++) {
        switch(rd()%NUMCHOICES) {
            case 0:
                res = builder.CreateMul(res,ly);
                control[3] *= control[1];
                break;
            case 1:
                res = builder.CreateMul(res,lz);
                control[3] *= control[2];
                break;
            case 2:
                lz = ensureNot0(block,F,lz,control[2]);
                res = builder.CreateSDiv(res,lz);
                control[3] /= control[2];
                break;
            case 3:
                ly = ensureNot0(block,F,ly,control[1]);
                res = builder.CreateSDiv(res,ly);
                control[3] /= control[1];
                break;
            case 4:
                res = builder.CreateAdd(res,ly);
                control[3] += control[1];
                break;
            case 5:
                res = builder.CreateAdd(res,lz);
                control[3] += control[2];
                break;
            case 6:
                res = builder.CreateAdd(res,res);
                control[3] += control[3];
                break;
            case 7:
                res = builder.CreateSub(res,ly);
                control[3] -= control[1];
                break;
            case 8:
                res = builder.CreateSub(res,lz);
                control[3] -= control[2];
                break;
            case 9:
                modby = dist8(g);
                res = builder.CreateSRem(res,ConstantInt::get(Type::getInt32Ty(F.getContext()),modby));
                control[3] %= modby;
                break;
            case 10:
                res = builder.CreateXor(res,ly);
                control[3] ^= control[1];
                break;
            case 11:
                res = builder.CreateXor(res,lz);
                control[3] ^= control[2];
                break;
            case 12:
                res = builder.CreateOr(res,ly);
                control[3] |= control[1];
                break;
            case 13:
                res = builder.CreateOr(res,lz);
                control[3] |= control[2];
                break;
            case 14:
                tmp = getRandGlobal();
                builder.CreateStore(res,tmp,true);
                break;
            case 15:
                randNumCtrl = 1+rd()%9;
                randNum = ConstantInt::get(Type::getInt32Ty(F.getContext()),randNumCtrl);
                res = builder.CreateAdd(ly,randNum);
                control[1] += randNumCtrl;
                break;
            case 16:
                randNumCtrl = 1+rd()%9;
                randNum = ConstantInt::get(Type::getInt32Ty(F.getContext()),randNumCtrl);
                res = builder.CreateAdd(lz,randNum);
                control[2] += randNumCtrl;
                break;
            default:
                break;
        }
    }

    res = ensureGT0(block,F,res,control[3]);
    controlVal = control[3];
    return res;
}

PreservedAnalyses BogusFlow::run(llvm::Module &M, llvm::ModuleAnalysisManager &) {
    bool changed = false;

    //create LowerSwitchPass to convert switches to if/else statements
    PassBuilder PB;
    FunctionAnalysisManager FPM;
    PB.registerFunctionAnalyses(FPM);
    llvm::LowerSwitchPass* lsp = new llvm::LowerSwitchPass();

    globals.clear();
    int distance = std::distance(M.begin(),M.end());
    if(!distance)
        return PreservedAnalyses::all();

    //create random number of global variables based on number of functions in module:
    int numGlobals = 1+rd()%distance;
    for(int i = 0; i < numGlobals; i++) {
        createGlobal(M);
    }

    //traverse all functions in module
    for(auto &F : M) {
        //ignore any external functions as we don't want to obfuscate those
        //TODO: only obfuscate specified functions
        if(F.isDeclaration())
            continue;

        //remove any switch statements for simplification
        PreservedAnalyses PR = lsp->run(F,FPM);

        //if all analyses are not preserved, function likely modified.
        //set changed to true if analyses aren't preserved or runOnFunction returns true.
        changed |= !PR.areAllPreserved();
        changed |= this->runOnFunction(F);
    }
    delete lsp;

    return (changed ? llvm::PreservedAnalyses::none()
            : llvm::PreservedAnalyses::all());
}

bool BogusFlow::runOnFunction(llvm::Function &F)
{
    vector<BasicBlock*> origBB;
    vector<BasicBlock*> allBB;

    bool changed = false;

    for(auto &B : F) {
        if(B.isEHPad() || B.isLandingPad() || containsPHI(B))
            continue;
        origBB.push_back(&B);
    }
    
    if(origBB.size() <= 1)
        return changed;

    origBB.erase(origBB.begin());
    allBB.insert(allBB.end(),origBB.begin(),origBB.end());

    for(auto &B : origBB) {
    //RET
    if(B->getTerminator()->getNumSuccessors() == 0)
      continue;
    
    // BasicBlock* predicateBlock = BasicBlock::Create(F.getContext(),"predicateBlock",&F);
    int controlVal;

    if(B->getTerminator()->getNumSuccessors() == 1) {
        if(allBB.empty())
            continue;

        BasicBlock* endSuccessor = B->getTerminator()->getSuccessor(0);
        if(containsPHI(*endSuccessor))
            continue;
        BasicBlock* predicateBlock = BasicBlock::Create(F.getContext(),"predicateBlock",&F);
        B->getTerminator()->eraseFromParent();
        BranchInst::Create(predicateBlock,B);
        Value* result = this->randomOperations(predicateBlock,F,controlVal,1+rd()%6);
        // result = builder.CreateSRem(result,ConstantInt::get(Type::getInt32Ty(F.getContext()),19));
        IRBuilder<> builder(predicateBlock);
        Value* cmp = builder.CreateICmpSGT(result,ConstantInt::get(Type::getInt32Ty(F.getContext()),0));
        BasicBlock* bogusOriginator = BasicBlock::Create(F.getContext(),"originator",&F);
        this->genFakeFlow(bogusOriginator,F,allBB,1+rd()%4);
        builder.CreateCondBr(cmp,endSuccessor,bogusOriginator);
        allBB.push_back(predicateBlock);
        changed = true;
    }
    }

    // fixStack(&F); //assume no PHIs created
    return changed;
}

llvm::PassPluginLibraryInfo getBogusFlowPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "bogus-flow", LLVM_VERSION_STRING,
            [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &FPM,
                    ArrayRef<PassBuilder::PipelineElement>) {
                    if(Name == "bogus-flow") {
                    FPM.addPass(BogusFlow());
                    return true;
                    }
                    return false;
                });
            }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return getBogusFlowPluginInfo();
}