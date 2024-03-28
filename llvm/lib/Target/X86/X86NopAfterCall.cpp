//==- X86NopAfterCall.cpp - Add a NOP whenever a call appears --=//
//

//===----------------------------------------------------------------------===//
/// \file
///
/// Pass that replaces nop instructions following a call in X86.
///
///
//===----------------------------------------------------------------------===//
#include "X86.h"
#include "X86InstrInfo.h"
#include "X86TargetMachine.h"
#include "MCTargetDesc/X86MCTargetDesc.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/Debug.h"
#include <iostream>

using namespace llvm;

#define PASS_KEY  "x86-nop-after-call"
#define DEBUG_TYPE PASS_KEY

namespace {
struct X86NopAfterCall final : public MachineFunctionPass {
  static char ID;
  X86NopAfterCall() : MachineFunctionPass(ID) {}
  StringRef getPassName() const override { return "X86 Nop After Call"; }
  bool runOnMachineFunction(MachineFunction &MF) override;
};
} // Namespace

char X86NopAfterCall::ID = 0;

bool X86NopAfterCall::runOnMachineFunction(MachineFunction &MF) {
  LLVM_DEBUG(dbgs() << getPassName() << "\n");

  bool Modified = false;

  const auto &ST = MF.getSubtarget<X86Subtarget>();
  const bool Is64Bit = ST.getTargetTriple().getArch() == Triple::x86_64;
  const unsigned CallOpc = Is64Bit ? X86::CALL64pcrel32 : X86::CALLpcrel16;
  for (MachineBasicBlock &MBB : MF){
    	for (MachineInstr &MI : MBB){
       		if (MI.getOpcode() == CallOpc) {
        		BuildMI(MBB, MI.getIterator(), MI.getDebugLoc(), ST.getInstrInfo()->get(X86::NOOP));
        		std::cout << "Nop After Call Pass " << std::endl;
        		Modified = true;
     		}
  	}
  }



  return Modified;
}

INITIALIZE_PASS(X86NopAfterCall, PASS_KEY, "X86 Nop After Call", false, false)

FunctionPass *llvm::createX86NopAfterCallPass() {
  return new X86NopAfterCall();
}
