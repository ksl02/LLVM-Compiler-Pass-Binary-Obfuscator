#include "IntegGuardCFGObf.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/ADT/STLExtras.h"

#include <sstream>
#include <string>
#include <iostream>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>

using namespace llvm;

#define DEBUG_TYPE "integrity-guard-cfg-obf"

#define CHOICES 7
#define PROB 5
#define SPLIT_BLOCK_PROB 5
#define RAND_NUM_INSTR_MAX 22
#define INJECT_PROB 30
#define JUNK_PROB 10

static GlobalVariable* getOrCreateZeroVar(Module &M, LLVMContext &CTX) {
    auto *I32 = IntegerType::getInt32Ty(CTX);
    ConstantInt *constZero = ConstantInt::get(I32, 0);

    GlobalVariable* zero = M.getGlobalVariable("zeroVar", true);
        if(!zero) {
            zero = new GlobalVariable(
                M,
                I32,
                false,
                GlobalVariable::InternalLinkage,
                constZero,
                "zeroVar");
        } else {
            if(!zero->hasInitializer())
                zero->setInitializer(constZero);
            }
        return zero;
}

//get/create expected value for global variable...
//if not expected, we can assume integrity checks failed and/or someone tampering
static GlobalVariable* getOrCreateExpected(Module &M, LLVMContext &CTX) {
    Constant *Init = ConstantInt::get(Type::getInt32Ty(CTX), 0x1000);

    GlobalVariable *expected = M.getGlobalVariable("globalCheck0x1000_expected", true);
    if(!expected) {
        expected = new GlobalVariable(
            M,
            IntegerType::getInt32Ty(CTX),
            false,
            GlobalValue::InternalLinkage,
            Init,
            "globalCheck0x1000_expected");
    } else {
        if(!expected->hasInitializer())
            expected->setInitializer(Init);
        expected->setLinkage(GlobalValue::InternalLinkage);
        expected->setConstant(false);
    }
    return expected;
}

static Value* randNonZeroInt(IRBuilder<> &B) {
    uint32_t r = (uint32_t)rand();
    r |= 1u;
    return ConstantInt::get(B.getInt32Ty(), r);
}

//generate random operations on guard variable so it's harder to distinguish true modifications to it
static Value* RandOperationsAt(IRBuilder<> &B, LLVMContext &CTX, Value* lhs) {
    auto *I32 = IntegerType::getInt32Ty(CTX);
    Value *rhs = randNonZeroInt(B);
    Value *result = lhs;

    int N = 1 + (rand() % RAND_NUM_INSTR_MAX);
    for(int i = 0; i < N; i++) {
        //randomly choose from instruction type to execute on the global variable with a nonzero local variable
        switch (rand() % CHOICES) {
            case 0: 
                result = B.CreateAdd(result, rhs);
                break;
            case 1:
                result = B.CreateSub(result, rhs);
                break;
            case 2:
                result = B.CreateSub(result, rhs);
                break;
            case 3:
                result = B.CreateOr(result, rhs);
                break;
            case 4:
                result = B.CreateAnd(result, rhs);
                break;
            case 5:
                result = B.CreateXor(result, rhs);
                break;
            case 6:
                result = B.CreateMul(result, rhs);
                break;
            default:
                break;
    }
        rhs = randNonZeroInt(B);
    }

    AllocaInst *Alloca = B.CreateAlloca(I32, nullptr, "");
    B.CreateStore(result, Alloca);
    return B.CreateLoad(I32, Alloca);
}

//inject junk / random operations to the global guard variable and then restore current value of global afterwards
static void injectJunkMods(LLVMContext &CTX, Instruction *IP, GlobalVariable *global) {
    IRBuilder<> B(IP);
    //save current value of global guard variable
    AllocaInst *save = B.CreateAlloca(Type::getInt32Ty(CTX), nullptr, "glob_save");
    Value *old = B.CreateLoad(Type::getInt32Ty(CTX), global, true);
    B.CreateStore(old, save);

    //write junk / random instructions on guard
    Value *Junk = RandOperationsAt(B, CTX, old);
    B.CreateStore(Junk, global, true);

    //restore old value of guard
    Value *restore = B.CreateLoad(Type::getInt32Ty(CTX), save);
    B.CreateStore(restore, global, true);
}

//insert if(guard != expected val of guard): call on_integrity_violation()
static void injectIntegrityValidate(Module &M, LLVMContext &CTX, Instruction *exitTerm, GlobalVariable *global, GlobalVariable *expected, FunctionCallee onIntegrityVioFunc) {
    IRBuilder<> B(exitTerm);

    Value *cur = B.CreateLoad(Type::getInt32Ty(CTX), global, true);
    Value *exp = B.CreateLoad(Type::getInt32Ty(CTX), expected, true);

    //obfuscate using a volatile zero variable as followed:
    //rhs = expectedval + (rand * load(zeroVar))
    //this makes rhs always expectedval, but is slightly more confusing since
    //zeroVar is volatile, so reverse engineers may not expect it to be zero
    //furthermore, zeroVar could optionally be set to a nonzero value on
    //integrity validation fails
    GlobalVariable *zero = getOrCreateZeroVar(M, CTX);
    Value *z = B.CreateLoad(Type::getInt32Ty(CTX), zero, true);
    Value *mask = B.CreateMul(randNonZeroInt(B), z);
    Value *rhs = B.CreateAdd(exp, mask);

    Value *bad = B.CreateICmpNE(cur, rhs);

    //create then block which runs before exit terminator
    Instruction *then = SplitBlockAndInsertIfThen(bad, exitTerm, false);
    IRBuilder<> TB(then);

    //inline integrity vio function so that reverse engineer cant just NOP all xrefs to func...
    //they would have to search for opcode patterns instead which makes it slightly harder
    //we call onIntegrityVioFunc only if guard != expected, otherwise just go to exit
    CallInst *C = TB.CreateCall(onIntegrityVioFunc);
    InlineFunctionInfo IFI;
    InlineFunction(*C, IFI);
}

bool IntegGuardCFGObf::runOnModule(Module &M) {
    srand(time(NULL));
    bool changed = false;
    auto &CTX = M.getContext();
    Type *I32 = Type::getInt32Ty(CTX);
    Constant *Init = ConstantInt::get(I32, 0x1000);

    //global guard var to be checked by on integrity checks
    GlobalVariable *global = M.getGlobalVariable("globalCheck0x1000");
    //create global if it doesn't exist
    if(!global) {
        global = new GlobalVariable(
            M,
            I32,
            false,
            GlobalValue::ExternalLinkage,
            Init,
            "globalCheck0x1000");
    } else {
        if(!global->hasInitializer())
            global->setInitializer(Init);
        global->setLinkage(GlobalValue::ExternalLinkage);
    }

    //get expected val
    GlobalVariable *expected = getOrCreateExpected(M, CTX);
    (void)getOrCreateZeroVar(M, CTX);

    for(auto &F : M) {
        if(F.isDeclaration())
            continue;

        StringRef N = F.getName();
        //ignore obfuscating and protecting integrity_guard and on_integrity_violation
        //in this module because that could create nasty recursion
        if(N == "integrity_guard" || N == "on_integrity_violation")
            continue;

        FunctionCallee integrityGuardFunc = M.getOrInsertFunction("integrity_guard", FunctionType::get(Type::getVoidTy(CTX), {}, false));
        FunctionCallee onIntegrityVioFunc = M.getOrInsertFunction("on_integrity_violation", FunctionType::get(Type::getVoidTy(CTX), {}, false));

        IRBuilder<> EntryBuilder(&*F.getEntryBlock().getFirstInsertionPt());
        auto *FType = FunctionType::get(EntryBuilder.getVoidTy(), false);

        //ARM32 ASM to trick a decompiler pseudocode view (for example IDA cannot resolve this branch properly, ends function instead)
        //save function arguments, then add to r0 pc + 0x20
        //perform operations to r0,r1,r2 that ultimately will lead to r0 remaining the same val
        //move r0 back to the pc, which is just pc before + 0x20 (which jumps to the pop instruction)
        //pop restores registers
        std::string Asm = R"(
        push {r0-r2}
        add r0, pc, #20
        mov r2, 0
        orr r1, r0, r2
        and r0, r0, r2
        mul r0, r1, r0
        eor r0, r1, r0
        mov pc, r0
        pop {r0-r2}
        )";
        InlineAsm *rawASM = InlineAsm::get(FType, Asm, "~{r0},~{r1},~{r2},~{cc},~{memory}", true, true);
        EntryBuilder.CreateCall(FType, rawASM);

        int i = 0;
        std::vector<AllocaInst*> allocas;
        std::vector<Type*> types;

        //inject some stack obf that does nothing
        for(auto &ARG : F.args()) {
            if(i == 3)
                break;
            Type* type = ARG.getType();
            AllocaInst *Alloca = EntryBuilder.CreateAlloca(type, nullptr, "ARG_" + std::to_string(i));
            EntryBuilder.CreateStore(&ARG, Alloca, true);
            allocas.push_back(Alloca);
            types.push_back(type);
            i++;
        }

        for(int j = 0; j < (int)allocas.size(); j++) {
            EntryBuilder.CreateLoad(types.at(j), allocas.at(j), true);
        }

        SmallVector<Instruction*, 128> ModifySites; //where to inject integrity guard func
        SmallVector<Instruction*, 128> junkSites; //where to inject junk code modifying guard var
        SmallVector<Instruction*, 64> ExitSites; //insts that exit func (i.e. return)

        for(BasicBlock &BB : F) {
            if(BB.isEHPad())
                continue;

            Instruction *T = BB.getTerminator();
            if(isa<ReturnInst>(T) || isa<UnreachableInst>(T) || isa<ResumeInst>(T)) {
                ExitSites.push_back(T);
            }

            for(Instruction &I : BB) {
                if(isa<PHINode>(I))
                    continue;
                if(I.isTerminator())
                    continue;

                if((rand() % INJECT_PROB) == 0) {
                    ModifySites.push_back(&I);
                }
                if((rand() % JUNK_PROB) == 0) {
                    junkSites.push_back(&I);
                }
            }
        }

        for(Instruction *IP : junkSites) {
            injectJunkMods(CTX, IP, global);
            changed = true;
        }

        for(Instruction *IP : ModifySites) {
            IRBuilder<> B(IP);
            //inline for same reason integ vio func inlined
            CallInst *C = B.CreateCall(integrityGuardFunc);
            InlineFunctionInfo IFI;
            InlineFunction(*C, IFI);
            changed = true;
        }

        for(Instruction *exitSite : ExitSites) {
            injectIntegrityValidate(M, CTX, exitSite, global, expected, onIntegrityVioFunc);
            changed = true;
        }
    }

    return changed;
}

PreservedAnalyses IntegGuardCFGObf::run(llvm::Module &M, llvm::ModuleAnalysisManager &) {
    bool changed = runOnModule(M);
    return (changed ? llvm::PreservedAnalyses::none()
                    : llvm::PreservedAnalyses::all());
}

llvm::PassPluginLibraryInfo getIntegGuardCFGObfPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "integrity-guard-cfg-obf", LLVM_VERSION_STRING,
            [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                    ArrayRef<PassBuilder::PipelineElement>) {
                    if(Name == "integrity-guard-cfg-obf") {
                        MPM.addPass(IntegGuardCFGObf());
                        return true;
                    }
                    return false;
                });
            }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return getIntegGuardCFGObfPluginInfo();
}