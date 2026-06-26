using Iced.Intel;
using System.Runtime.InteropServices;

namespace Il2CppInterop.Common.XrefScans;

public static class XrefScannerLowLevel
{
    public static readonly bool IsArm64 = RuntimeInformation.ProcessArchitecture == Architecture.Arm64;

    public static IEnumerable<IntPtr> JumpTargets(IntPtr codeStart, bool ignoreRetn = false)
    {
        if (IsArm64)
            return JumpTargetsImplArm64(codeStart, ignoreRetn);
        return JumpTargetsImpl(XrefScanner.DecoderForAddress(codeStart), ignoreRetn);
    }

    // arm64: same walk as JumpTargetsImplArm64 (identical termination logic, so the function is
    // bounded the same way), but tags each yielded target as a call (BL) or an unconditional
    // branch (B). The injection hooks need this distinction: on arm64 the resolve chain continues
    // through a *tail-call* (B to another function), while the x86 ".Last()" heuristic blindly
    // grabs whatever the last flow-control target is — which on arm64 is usually a PLT/helper BL.
    public static IEnumerable<(IntPtr target, bool isCall)> JumpTargetsArm64Tagged(IntPtr codeStart, bool ignoreRetn = false)
    {
        const int MaxInstructions = 4096;
        var firstFlowControl = true;
        var basePc = (long)codeStart;

        for (var i = 0; i < MaxInstructions; i++)
        {
            var addr = basePc + i * 4;
            var instr = (uint)Marshal.ReadInt32((IntPtr)addr);

            if ((instr & 0xFFFFFC1Fu) == 0xD65F0000u) // RET
            {
                if (!ignoreRetn) yield break;
                firstFlowControl = false;
                continue;
            }

            if ((instr & 0xFFE0001Fu) == 0xD4200000u || instr == 0u) // BRK / padding
                yield break;

            var isB = (instr & 0xFC000000u) == 0x14000000u;
            var isBL = (instr & 0xFC000000u) == 0x94000000u;
            if (isB || isBL)
            {
                long imm26 = instr & 0x03FFFFFFu;
                if ((imm26 & 0x02000000L) != 0) imm26 |= unchecked((long)0xFFFFFFFFFC000000UL);
                yield return ((IntPtr)(addr + (imm26 << 2)), isBL);
                if (firstFlowControl && isB) yield break;
                firstFlowControl = false;
                continue;
            }

            var isCondB = (instr & 0xFF000010u) == 0x54000000u;
            var isBrBlr = (instr & 0xFFFFFC1Fu) == 0xD61F0000u || (instr & 0xFFFFFC1Fu) == 0xD63F0000u;
            var isCmpB = (instr & 0x7E000000u) == 0x34000000u || (instr & 0x7E000000u) == 0x36000000u;
            if (isCondB || isBrBlr || isCmpB)
                firstFlowControl = false;
        }
    }

    // arm64: if `fn` is a single-instruction veneer/thunk (first instruction is an unconditional B
    // to another function), follow the chain to the real function entry. il2cpp's arm64 codegen
    // routes some exports through a 4-byte `b real` thunk that is wedged immediately before an
    // *unrelated* function; detouring the thunk would overwrite that neighbor (a far detour writes a
    // ~16-byte LDR/BR stub), so the hook must resolve through the thunk and detour the real function.
    public static IntPtr Arm64ResolveThunk(IntPtr fn)
    {
        for (var hops = 0; hops < 8 && fn != IntPtr.Zero; hops++)
        {
            var instr = (uint)Marshal.ReadInt32(fn);
            if ((instr & 0xFC000000u) != 0x14000000u) break; // not an unconditional B -> real entry
            long imm26 = instr & 0x03FFFFFFu;
            if ((imm26 & 0x02000000L) != 0) imm26 |= unchecked((long)0xFFFFFFFFFC000000UL);
            fn = (IntPtr)((long)fn + (imm26 << 2));
        }
        return fn;
    }

    // arm64: given an address inside a function, walk backwards to the function's first instruction
    // (the instruction immediately after the previous function's terminator: RET / BRK / padding).
    // Used to recover a function entry point (e.g. the 3-param GenericMethod::GetMethod) from a
    // pointer that lands inside or just after it.
    public static IntPtr Arm64FunctionStart(IntPtr inside)
    {
        var a = (long)inside;
        for (var i = 1; i < 8192; i++)
        {
            var addr = a - i * 4;
            var instr = (uint)Marshal.ReadInt32((IntPtr)addr);
            if ((instr & 0xFFFFFC1Fu) == 0xD65F0000u ||                       // RET
                (instr & 0xFFE0001Fu) == 0xD4200000u || instr == 0u)          // BRK / padding
                return (IntPtr)(addr + 4);
        }
        return IntPtr.Zero;
    }

    // AArch64 version of JumpTargetsImpl. Instructions are fixed 4 bytes, so we decode the branch
    // instructions directly: BL (call) and B (unconditional branch) carry a sign-extended imm26
    // PC-relative target; RET ends the function. Mirrors the x86 walk (yield call/branch targets in
    // order, stop at the first leading tail-branch or at a return). Feeding arm64 bytes to the x86
    // Iced decoder mis-decodes and runs off into protected memory (AccessViolation) — this avoids that.
    private static IEnumerable<IntPtr> JumpTargetsImplArm64(IntPtr codeStart, bool ignoreRetn)
    {
        const int MaxInstructions = 4096;
        var firstFlowControl = true;
        var basePc = (long)codeStart;

        for (var i = 0; i < MaxInstructions; i++)
        {
            var addr = basePc + i * 4;
            var instr = (uint)Marshal.ReadInt32((IntPtr)addr);

            // RET (any Rn): 0xD65F0000 | (Rn<<5)
            if ((instr & 0xFFFFFC1Fu) == 0xD65F0000u)
            {
                if (!ignoreRetn) yield break;
                firstFlowControl = false;
                continue;
            }

            // BRK / zero-fill padding -> end of function
            if ((instr & 0xFFE0001Fu) == 0xD4200000u || instr == 0u)
                yield break;

            var isB = (instr & 0xFC000000u) == 0x14000000u;   // B  (unconditional immediate branch)
            var isBL = (instr & 0xFC000000u) == 0x94000000u;  // BL (branch-with-link = call)
            if (isB || isBL)
            {
                long imm26 = instr & 0x03FFFFFFu;
                if ((imm26 & 0x02000000L) != 0) imm26 |= unchecked((long)0xFFFFFFFFFC000000UL); // sign-extend bit 25
                var target = addr + (imm26 << 2);
                yield return (IntPtr)target;
                if (firstFlowControl && isB) yield break;   // a leading unconditional branch == tail call
                firstFlowControl = false;
                continue;
            }

            // any other control flow closes the "first flow control" window
            var isCondB = (instr & 0xFF000010u) == 0x54000000u;                                          // B.cond
            var isBrBlr = (instr & 0xFFFFFC1Fu) == 0xD61F0000u || (instr & 0xFFFFFC1Fu) == 0xD63F0000u;  // BR / BLR (indirect)
            var isCmpB = (instr & 0x7E000000u) == 0x34000000u || (instr & 0x7E000000u) == 0x36000000u;   // CBZ/CBNZ / TBZ/TBNZ
            if (isCondB || isBrBlr || isCmpB)
                firstFlowControl = false;
        }
    }

    private static IEnumerable<IntPtr> JumpTargetsImpl(Decoder myDecoder, bool ignoreRetn)
    {
        var firstFlowControl = true;

        while (true)
        {
            myDecoder.Decode(out var instruction);
            if (myDecoder.LastError == DecoderError.NoMoreBytes) yield break;

            // 0xcc - padding after most functions
            if (instruction.Mnemonic == Mnemonic.Int3)
                yield break;

            if (instruction.FlowControl == FlowControl.Return && !ignoreRetn)
                yield break;

            if (instruction.FlowControl == FlowControl.UnconditionalBranch ||
                instruction.FlowControl == FlowControl.Call)
            {
                // We hope and pray that the compiler didn't use short jumps for any function calls
                if (!instruction.IsJmpShort)
                {
                    yield return (IntPtr)ExtractTargetAddress(in instruction);
                    if (firstFlowControl && instruction.FlowControl == FlowControl.UnconditionalBranch) yield break;
                }
            }

            if (instruction.FlowControl != FlowControl.Next)
            {
                firstFlowControl = false;
            }
        }
    }

    public static IEnumerable<IntPtr> CallAndIndirectTargets(IntPtr pointer)
    {
        return CallAndIndirectTargetsImpl(XrefScanner.DecoderForAddress(pointer, 1024 * 1024));
    }

    private static IEnumerable<IntPtr> CallAndIndirectTargetsImpl(Decoder decoder)
    {
        while (true)
        {
            decoder.Decode(out var instruction);
            if (decoder.LastError == DecoderError.NoMoreBytes) yield break;

            if (instruction.FlowControl == FlowControl.Return)
                yield break;

            if (instruction.Mnemonic == Mnemonic.Int || instruction.Mnemonic == Mnemonic.Int1)
                yield break;

            if (instruction.Mnemonic == Mnemonic.Call || instruction.Mnemonic == Mnemonic.Jmp)
            {
                var targetAddress = XrefScanner.ExtractTargetAddress(instruction);
                if (targetAddress != 0)
                    yield return (IntPtr)targetAddress;
                continue;
            }

            if (instruction.Mnemonic == Mnemonic.Lea)
                if (instruction.MemoryBase == Register.RIP)
                {
                    var targetAddress = instruction.IPRelativeMemoryAddress;
                    if (targetAddress != 0)
                        yield return (IntPtr)targetAddress;
                }
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
                // PATCH (macOS experiment): clang emits indirect/jump-table branches whose Op0Kind
                // is Memory/Register, not a near/far immediate. Upstream throws here; we degrade
                // gracefully like XrefScanner.ExtractTargetAddress (return 0 = "no static target").
                return 0;
        }
    }
}
