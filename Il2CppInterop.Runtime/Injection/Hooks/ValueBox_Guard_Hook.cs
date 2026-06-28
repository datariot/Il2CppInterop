using System;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Il2CppInterop.Common;
using Il2CppInterop.Common.XrefScans;
using Il2CppInterop.Runtime.Runtime;
using Microsoft.Extensions.Logging;

namespace Il2CppInterop.Runtime.Injection.Hooks
{
    // arm64 diagnostic + crash guard. On arm64, during Mod Helper ModContent registration, an injected
    // method executes and somewhere inside it boxes a value type from a NULL data pointer ->
    // il2cpp_value_box(klass, NULL) -> Object::Box memmove(dest, src=NULL, instance_size-0x10) -> SIGSEGV
    // (GA RVA 0x66c1d4, reached via il2cpp_runtime_invoke's void-return path with returnStorage=NULL).
    // The offending value_box is emitted directly in the generated interop assemblies, so a managed-side
    // guard in Il2CppInterop.Runtime never sees it. Detour the export itself so EVERY caller is covered:
    // log the klass once and return null instead of crashing, to identify the value type and keep going.
    internal unsafe class ValueBox_Guard_Hook : Hook<ValueBox_Guard_Hook.MethodDelegate>
    {
        public override string TargetMethodName => "Object::Box (il2cpp_value_box)";
        public override MethodDelegate GetDetour() => Hook;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate IntPtr MethodDelegate(IntPtr klass, IntPtr data);

        private static readonly ConcurrentDictionary<IntPtr, byte> s_LoggedKlasses = new();

        private IntPtr Hook(IntPtr klass, IntPtr data)
        {
            if (data == IntPtr.Zero)
            {
                if (s_LoggedKlasses.TryAdd(klass, 0))
                {
                    string name = "<null klass>";
                    string ns = "";
                    if (klass != IntPtr.Zero)
                    {
                        try { name = IL2CPP.il2cpp_class_get_name_(klass) ?? "<?>"; } catch { }
                        try { ns = IL2CPP.il2cpp_class_get_namespace_(klass) ?? ""; } catch { }
                    }
                    Logger.Instance.LogWarning(
                        "[arm64-box-native] il2cpp_value_box NULL data for valuetype '{Ns}{Dot}{Name}' (klass=0x{Addr}) -> returning null (would have crashed)",
                        ns, ns.Length > 0 ? "." : "", name, klass.ToInt64().ToString("X"));
                }

                return IntPtr.Zero;
            }

            return Original(klass, data);
        }

        public override IntPtr FindTargetMethod()
        {
            var valueBoxAPI = InjectorHelpers.GetIl2CppExport(nameof(IL2CPP.il2cpp_value_box));
            Logger.Instance.LogTrace("il2cpp_value_box: 0x{Addr}", valueBoxAPI.ToInt64().ToString("X2"));

            // arm64: the export is a 4-byte `b real` thunk; detour the real function, not the thunk.
            if (XrefScannerLowLevel.IsArm64)
                return XrefScannerLowLevel.Arm64ResolveThunk(valueBoxAPI);
            return valueBoxAPI;
        }

        public override void TargetMethodNotFound()
        {
            Logger.Instance.LogWarning("il2cpp_value_box guard hook target not found; skipping (non-fatal).");
        }
    }
}
