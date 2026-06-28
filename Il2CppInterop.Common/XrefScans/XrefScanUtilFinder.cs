using System.Runtime.InteropServices;
using Iced.Intel;

namespace Il2CppInterop.Common.XrefScans;

internal static class XrefScanUtilFinder
{
    private static readonly bool IsArm64 = RuntimeInformation.ProcessArchitecture == Architecture.Arm64;

    // Returns the absolute address of the il2cpp metadata-init *token* operand (the location the token
    // value is read from) that is passed to the metadata-init helper called at `callTarget`.
    public static IntPtr FindLastRcxReadAddressBeforeCallTo(IntPtr codeStart, IntPtr callTarget)
    {
        if (IsArm64)
            return FindLastArgLoadAddressBeforeCallToArm64(codeStart, callTarget);

        var decoder = XrefScanner.DecoderForAddress(codeStart);
        var lastRcxRead = IntPtr.Zero;

        while (true)
        {
            decoder.Decode(out var instruction);
            if (decoder.LastError == DecoderError.NoMoreBytes) return IntPtr.Zero;

            if (instruction.FlowControl == FlowControl.Return)
                return IntPtr.Zero;

            if (instruction.FlowControl == FlowControl.UnconditionalBranch)
                continue;

            if (instruction.Mnemonic == Mnemonic.Int || instruction.Mnemonic == Mnemonic.Int1)
                return IntPtr.Zero;

            if (instruction.Mnemonic == Mnemonic.Call)
            {
                var target = ExtractTargetAddress(instruction);
                if ((IntPtr)target == callTarget)
                    return lastRcxRead;
            }

            if (instruction.Mnemonic == Mnemonic.Mov)
                if (instruction.Op0Kind == OpKind.Register && instruction.Op0Register == Register.ECX &&
                    instruction.Op1Kind == OpKind.Memory && instruction.IsIPRelativeMemoryOperand)
                {
                    var movTarget = (IntPtr)instruction.IPRelativeMemoryAddress;
                    if (instruction.MemorySize != MemorySize.UInt32 && instruction.MemorySize != MemorySize.Int32)
                        continue;

                    lastRcxRead = movTarget;
                }
        }
    }

    // Returns the absolute address of the byte-sized init flag that is stored to right after the
    // metadata-init helper call at `callTarget`.
    public static IntPtr FindByteWriteTargetRightAfterCallTo(IntPtr codeStart, IntPtr callTarget)
    {
        if (IsArm64)
            return FindByteWriteTargetRightAfterCallToArm64(codeStart, callTarget);

        var decoder = XrefScanner.DecoderForAddress(codeStart);
        var seenCall = false;

        while (true)
        {
            decoder.Decode(out var instruction);
            if (decoder.LastError == DecoderError.NoMoreBytes) return IntPtr.Zero;

            if (instruction.FlowControl == FlowControl.Return)
                return IntPtr.Zero;

            if (instruction.FlowControl == FlowControl.UnconditionalBranch)
                continue;

            if (instruction.Mnemonic == Mnemonic.Int || instruction.Mnemonic == Mnemonic.Int1)
                return IntPtr.Zero;

            if (instruction.Mnemonic == Mnemonic.Call)
            {
                var target = ExtractTargetAddress(instruction);
                if ((IntPtr)target == callTarget)
                    seenCall = true;
            }

            if (instruction.Mnemonic == Mnemonic.Mov && seenCall)
                if (instruction.Op0Kind == OpKind.Memory && (instruction.MemorySize == MemorySize.Int8 ||
                                                             instruction.MemorySize == MemorySize.UInt8))
                    return (IntPtr)instruction.IPRelativeMemoryAddress;
        }
    }

    private static ulong ExtractTargetAddress(in Instruction instruction)
    {
        switch (instruction.Op0Kind)
        {
            case OpKind.NearBranch16:
                return instruction.NearBranch16;
            case OpKind.NearBranch32:
                return instruction.NearBranch32;
            case OpKind.NearBranch64:
                return instruction.NearBranch64;
            case OpKind.FarBranch16:
                return instruction.FarBranch16;
            case OpKind.FarBranch32:
                return instruction.FarBranch32;
            default:
                return 0;
        }
    }

    // ---------------------------------------------------------------------------------------------
    // arm64 (AArch64) implementations.
    //
    // il2cpp's arm64 metadata-init guard at a method's prologue looks like:
    //     ADRP  x0, tokenPage          ; PC-relative page of the metadata token
    //     LDR   w0, [x0, #tokenOff]    ; w0 = token value  (first arg, AAPCS x0/w0 — NOT rcx)
    //     BL    il2cpp_codegen_initialize_method   ; == callTarget
    //     ADRP  x8, flagPage
    //     MOV   w9, #1
    //     STRB  w9, [x8, #flagOff]     ; mark this method initialized (byte store)
    //
    // The x86 finders look for `mov ecx, [rip+d]` (token) and the byte `mov [rip+d], ..` (flag) and
    // return the absolute operand address. These arm64 versions reconstruct the same absolute address
    // from ADRP(+ADD/LDR/STRB) pairs, hand-decoding instructions exactly like JumpTargetsImplArm64.
    // ---------------------------------------------------------------------------------------------

    private const int Arm64MaxInstructions = 4096;

    private static IntPtr FindLastArgLoadAddressBeforeCallToArm64(IntPtr codeStart, IntPtr callTarget)
    {
        var basePc = (long)codeStart;
        // Per-register resolved ADRP page base (0 == unset; il2cpp never targets page 0 here).
        var adrpPage = new long[32];
        var lastArgAddr = IntPtr.Zero; // last absolute address loaded into / formed in x0 (the first arg)

        for (var i = 0; i < Arm64MaxInstructions; i++)
        {
            var addr = basePc + i * 4;
            var instr = (uint)Marshal.ReadInt32((IntPtr)addr);

            if ((instr & 0xFFFFFC1Fu) == 0xD65F0000u) // RET
                return IntPtr.Zero;
            if ((instr & 0xFFE0001Fu) == 0xD4200000u || instr == 0u) // BRK / padding
                return IntPtr.Zero;

            // BL (call): if it targets the metadata-init helper, return the last address put in x0.
            if ((instr & 0xFC000000u) == 0x94000000u)
            {
                long imm26 = instr & 0x03FFFFFFu;
                if ((imm26 & 0x02000000L) != 0) imm26 |= unchecked((long)0xFFFFFFFFFC000000UL);
                var target = addr + (imm26 << 2);
                if ((IntPtr)target == callTarget)
                    return lastArgAddr;
                continue;
            }

            if (TryDecodeAdrp(instr, addr, out var adrpRd, out var adrpTarget))
            {
                adrpPage[adrpRd] = adrpTarget;
                continue;
            }

            // ADD (64-bit immediate): Xd = Xn + imm12(<<12 if sh). Forms an address-of into Xd.
            if ((instr & 0xFF800000u) == 0x91000000u)
            {
                var rd = (int)(instr & 0x1F);
                var rn = (int)((instr >> 5) & 0x1F);
                var imm12 = (long)((instr >> 10) & 0xFFF);
                if (((instr >> 22) & 1) != 0) imm12 <<= 12;
                if (adrpPage[rn] != 0)
                {
                    var resolved = adrpPage[rn] + imm12;
                    adrpPage[rd] = resolved; // propagate (e.g. ADRP x0; ADD x0,x0,#off)
                    if (rd == 0) lastArgAddr = (IntPtr)resolved;
                }
                continue;
            }

            // LDR (immediate, unsigned offset), 32- or 64-bit: Wt/Xt = [Xn + imm12<<scale].
            // The operand *address* (Xn + off) is the token storage location — matches x86 semantics.
            if ((instr & 0xBFC00000u) == 0xB9400000u)
            {
                var size = (int)(instr >> 30); // 2 = 32-bit (LDR Wt), 3 = 64-bit (LDR Xt)
                var rt = (int)(instr & 0x1F);
                var rn = (int)((instr >> 5) & 0x1F);
                var imm12 = (long)((instr >> 10) & 0xFFF);
                if (adrpPage[rn] != 0 && rt == 0)
                    lastArgAddr = (IntPtr)(adrpPage[rn] + (imm12 << size));
                continue;
            }
        }

        return IntPtr.Zero;
    }

    private static IntPtr FindByteWriteTargetRightAfterCallToArm64(IntPtr codeStart, IntPtr callTarget)
    {
        var basePc = (long)codeStart;
        var adrpPage = new long[32];
        var seenCall = false;

        for (var i = 0; i < Arm64MaxInstructions; i++)
        {
            var addr = basePc + i * 4;
            var instr = (uint)Marshal.ReadInt32((IntPtr)addr);

            if ((instr & 0xFFFFFC1Fu) == 0xD65F0000u) // RET
                return IntPtr.Zero;
            if ((instr & 0xFFE0001Fu) == 0xD4200000u || instr == 0u) // BRK / padding
                return IntPtr.Zero;

            if ((instr & 0xFC000000u) == 0x94000000u) // BL
            {
                long imm26 = instr & 0x03FFFFFFu;
                if ((imm26 & 0x02000000L) != 0) imm26 |= unchecked((long)0xFFFFFFFFFC000000UL);
                var target = addr + (imm26 << 2);
                if ((IntPtr)target == callTarget)
                    seenCall = true;
                continue;
            }

            if (TryDecodeAdrp(instr, addr, out var adrpRd, out var adrpTarget))
            {
                adrpPage[adrpRd] = adrpTarget;
                continue;
            }

            // ADD immediate — propagate address-of into Xd (covers ADRP x8; ADD x8,x8,#off; STRB ...).
            if ((instr & 0xFF800000u) == 0x91000000u)
            {
                var rd = (int)(instr & 0x1F);
                var rn = (int)((instr >> 5) & 0x1F);
                var imm12 = (long)((instr >> 10) & 0xFFF);
                if (((instr >> 22) & 1) != 0) imm12 <<= 12;
                if (adrpPage[rn] != 0) adrpPage[rd] = adrpPage[rn] + imm12;
                continue;
            }

            // STRB (immediate, unsigned offset): [Xn + imm12] = Wt. The init-flag store after the call.
            if (seenCall && (instr & 0xFFC00000u) == 0x39000000u)
            {
                var rn = (int)((instr >> 5) & 0x1F);
                var imm12 = (long)((instr >> 10) & 0xFFF);
                if (adrpPage[rn] != 0)
                    return (IntPtr)(adrpPage[rn] + imm12);
            }
        }

        return IntPtr.Zero;
    }

    // ADRP Xd, <PC-relative page>: 1 immlo(2) 1 0000 immhi(19) Rd(5). imm = (immhi:immlo) << 12,
    // sign-extended from 33 bits; target = (PC & ~0xFFF) + imm.
    private static bool TryDecodeAdrp(uint instr, long pc, out int rd, out long target)
    {
        rd = (int)(instr & 0x1F);
        target = 0;
        if ((instr & 0x9F000000u) != 0x90000000u) // ADRP opcode (ADR has bit31=0; excluded)
            return false;

        long immlo = (instr >> 29) & 0x3;
        long immhi = (instr >> 5) & 0x7FFFF; // 19 bits
        long imm = (immhi << 2) | immlo;     // 21-bit page count
        if ((imm & 0x100000L) != 0) imm |= unchecked((long)0xFFFFFFFFFFE00000UL); // sign-extend bit 20
        target = (pc & ~0xFFFL) + (imm << 12);
        return true;
    }
}
