; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mtriple=thumbv8.1m.main-none-none-eabi -mattr=+mve -verify-machineinstrs %s -o - | FileCheck %s

define arm_aapcs_vfpcc void @reg(<8 x i16> %acc0, <8 x i16> %acc1, i32* nocapture %px, i16 signext %p0) {
; CHECK-LABEL: reg:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    .save {r4, r6, r7, lr}
; CHECK-NEXT:    push {r4, r6, r7, lr}
; CHECK-NEXT:    .pad #8
; CHECK-NEXT:    sub sp, #8
; CHECK-NEXT:    movw r1, #52428
; CHECK-NEXT:    vmsr p0, r1
; CHECK-NEXT:    movw r1, #13107
; CHECK-NEXT:    vstr p0, [sp, #4] @ 4-byte Spill
; CHECK-NEXT:    vpst
; CHECK-NEXT:    vaddvt.s16 r12, q1
; CHECK-NEXT:    vmsr p0, r1
; CHECK-NEXT:    vstr p0, [sp] @ 4-byte Spill
; CHECK-NEXT:    vpst
; CHECK-NEXT:    vaddvt.s16 r2, q1
; CHECK-NEXT:    vldr p0, [sp, #4] @ 4-byte Reload
; CHECK-NEXT:    vpst
; CHECK-NEXT:    vaddvt.s16 r4, q0
; CHECK-NEXT:    vldr p0, [sp] @ 4-byte Reload
; CHECK-NEXT:    vpst
; CHECK-NEXT:    vaddvt.s16 r6, q0
; CHECK-NEXT:    strd r6, r4, [r0]
; CHECK-NEXT:    strd r2, r12, [r0, #8]
; CHECK-NEXT:    add sp, #8
; CHECK-NEXT:    pop {r4, r6, r7, pc}
entry:
  %0 = tail call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 13107)
  %1 = tail call i32 @llvm.arm.mve.addv.predicated.v8i16.v8i1(<8 x i16> %acc0, i32 0, <8 x i1> %0)
  %2 = tail call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 52428)
  %3 = tail call i32 @llvm.arm.mve.addv.predicated.v8i16.v8i1(<8 x i16> %acc0, i32 0, <8 x i1> %2)
  %4 = tail call i32 @llvm.arm.mve.addv.predicated.v8i16.v8i1(<8 x i16> %acc1, i32 0, <8 x i1> %0)
  %5 = tail call i32 @llvm.arm.mve.addv.predicated.v8i16.v8i1(<8 x i16> %acc1, i32 0, <8 x i1> %2)
  store i32 %1, i32* %px, align 4
  %arrayidx1 = getelementptr inbounds i32, i32* %px, i32 1
  store i32 %3, i32* %arrayidx1, align 4
  %arrayidx2 = getelementptr inbounds i32, i32* %px, i32 2
  store i32 %4, i32* %arrayidx2, align 4
  %arrayidx3 = getelementptr inbounds i32, i32* %px, i32 3
  store i32 %5, i32* %arrayidx3, align 4
  ret void
}


define arm_aapcs_vfpcc void @const(<8 x i16> %acc0, <8 x i16> %acc1, i32* nocapture %px, i16 signext %p0) {
; CHECK-LABEL: const:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    .save {r4, r6, r7, lr}
; CHECK-NEXT:    push {r4, r6, r7, lr}
; CHECK-NEXT:    uxth r2, r1
; CHECK-NEXT:    mvns r1, r1
; CHECK-NEXT:    vmsr p0, r2
; CHECK-NEXT:    uxth r1, r1
; CHECK-NEXT:    vpstt
; CHECK-NEXT:    vaddvt.s16 r12, q1
; CHECK-NEXT:    vaddvt.s16 r2, q0
; CHECK-NEXT:    vmsr p0, r1
; CHECK-NEXT:    vpstt
; CHECK-NEXT:    vaddvt.s16 r4, q1
; CHECK-NEXT:    vaddvt.s16 r6, q0
; CHECK-NEXT:    stm.w r0, {r2, r6, r12}
; CHECK-NEXT:    str r4, [r0, #12]
; CHECK-NEXT:    pop {r4, r6, r7, pc}
entry:
  %0 = zext i16 %p0 to i32
  %1 = tail call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 %0)
  %2 = tail call i32 @llvm.arm.mve.addv.predicated.v8i16.v8i1(<8 x i16> %acc0, i32 0, <8 x i1> %1)
  %3 = xor i16 %p0, -1
  %4 = zext i16 %3 to i32
  %5 = tail call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 %4)
  %6 = tail call i32 @llvm.arm.mve.addv.predicated.v8i16.v8i1(<8 x i16> %acc0, i32 0, <8 x i1> %5)
  %7 = tail call i32 @llvm.arm.mve.addv.predicated.v8i16.v8i1(<8 x i16> %acc1, i32 0, <8 x i1> %1)
  %8 = tail call i32 @llvm.arm.mve.addv.predicated.v8i16.v8i1(<8 x i16> %acc1, i32 0, <8 x i1> %5)
  store i32 %2, i32* %px, align 4
  %arrayidx1 = getelementptr inbounds i32, i32* %px, i32 1
  store i32 %6, i32* %arrayidx1, align 4
  %arrayidx2 = getelementptr inbounds i32, i32* %px, i32 2
  store i32 %7, i32* %arrayidx2, align 4
  %arrayidx3 = getelementptr inbounds i32, i32* %px, i32 3
  store i32 %8, i32* %arrayidx3, align 4
  ret void
}



define arm_aapcs_vfpcc <4 x i32> @xorvpnot_i32(<4 x i32> %acc0, i16 signext %p0) {
; CHECK-LABEL: xorvpnot_i32:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    mvns r0, r0
; CHECK-NEXT:    vmov.i32 q1, #0x0
; CHECK-NEXT:    uxth r0, r0
; CHECK-NEXT:    vmsr p0, r0
; CHECK-NEXT:    vpsel q0, q0, q1
; CHECK-NEXT:    bx lr
entry:
  %l3 = xor i16 %p0, -1
  %l4 = zext i16 %l3 to i32
  %l5 = tail call <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32 %l4)
  %l6 = select <4 x i1> %l5, <4 x i32> %acc0, <4 x i32> zeroinitializer
  ret <4 x i32> %l6
}

define arm_aapcs_vfpcc <8 x i16> @xorvpnot_i16(<8 x i16> %acc0, i16 signext %p0) {
; CHECK-LABEL: xorvpnot_i16:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    mvns r0, r0
; CHECK-NEXT:    vmov.i32 q1, #0x0
; CHECK-NEXT:    uxth r0, r0
; CHECK-NEXT:    vmsr p0, r0
; CHECK-NEXT:    vpsel q0, q0, q1
; CHECK-NEXT:    bx lr
entry:
  %l3 = xor i16 %p0, -1
  %l4 = zext i16 %l3 to i32
  %l5 = tail call <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32 %l4)
  %l6 = select <8 x i1> %l5, <8 x i16> %acc0, <8 x i16> zeroinitializer
  ret <8 x i16> %l6
}

define arm_aapcs_vfpcc <16 x i8> @xorvpnot_i8(<16 x i8> %acc0, i16 signext %p0) {
; CHECK-LABEL: xorvpnot_i8:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    mvns r0, r0
; CHECK-NEXT:    vmov.i32 q1, #0x0
; CHECK-NEXT:    uxth r0, r0
; CHECK-NEXT:    vmsr p0, r0
; CHECK-NEXT:    vpsel q0, q0, q1
; CHECK-NEXT:    bx lr
entry:
  %l3 = xor i16 %p0, -1
  %l4 = zext i16 %l3 to i32
  %l5 = tail call <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32 %l4)
  %l6 = select <16 x i1> %l5, <16 x i8> %acc0, <16 x i8> zeroinitializer
  ret <16 x i8> %l6
}



declare i32 @llvm.arm.mve.pred.v2i.v4i1(<4 x i1>)
declare i32 @llvm.arm.mve.pred.v2i.v8i1(<8 x i1>)
declare i32 @llvm.arm.mve.pred.v2i.v16i1(<16 x i1>)

declare <4 x i1> @llvm.arm.mve.pred.i2v.v4i1(i32)
declare <8 x i1> @llvm.arm.mve.pred.i2v.v8i1(i32)
declare <16 x i1> @llvm.arm.mve.pred.i2v.v16i1(i32)

declare i32 @llvm.arm.mve.addv.predicated.v4i32.v4i1(<4 x i32>, i32, <4 x i1>)
declare i32 @llvm.arm.mve.addv.predicated.v8i16.v8i1(<8 x i16>, i32, <8 x i1>)
declare i32 @llvm.arm.mve.addv.predicated.v16i8.v16i1(<16 x i8>, i32, <16 x i1>)
