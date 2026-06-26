using System;
using System.Linq;
using System.Runtime.InteropServices;
using Il2CppInterop.Common;
using Il2CppInterop.Common.XrefScans;
using Il2CppInterop.Runtime.Runtime;
using Il2CppInterop.Runtime.Startup;
using Microsoft.Extensions.Logging;

namespace Il2CppInterop.Runtime.Injection.Hooks
{
    /// Unity 6 (6000.x.x): the 1-param GetMethod(const Il2CppGenericMethod&amp;) is inlined into
    /// the 3-param GetMethod(const MethodInfo*, const Il2CppGenericInst*, const Il2CppGenericInst*).
    /// We use the hook with 3 param correctly
    internal unsafe class GenericMethod_GetMethod_Unity6_Hook : Hook<GenericMethod_GetMethod_Unity6_Hook.MethodDelegate>
    {
        public override string TargetMethodName => "GenericMethod::GetMethod";
        public override MethodDelegate GetDetour() => Hook;

        // CRITICAL: Use Cdecl for Linux x64 (System V ABI)
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate Il2CppMethodInfo* MethodDelegate(Il2CppMethodInfo* methodDefinition, Il2CppGenericInst* classInst, Il2CppGenericInst* methodInst);

        private Il2CppMethodInfo* Hook(Il2CppMethodInfo* methodDefinition, Il2CppGenericInst* classInst, Il2CppGenericInst* methodInst)
        {
            // Direct pass-through if the definition is null for safety
            if (methodDefinition == null)
                return Original(methodDefinition, classInst, methodInst);

            try
            {
                // Check if the dictionary even exists before trying to access it
                if (ClassInjector.InflatedMethodFromContextDictionary == null)
                    return Original(methodDefinition, classInst, methodInst);

                if (ClassInjector.InflatedMethodFromContextDictionary.TryGetValue((IntPtr)methodDefinition, out var methods))
                {
                    // If the dictionary entry is malformed, skip
                    if (methods.Item1 == null || methods.Item2 == null)
                        return Original(methodDefinition, classInst, methodInst);

                    // If it's a class-level generic without method generics, methodInst is null
                    if (methodInst == null)
                        return Original(methodDefinition, classInst, methodInst);

                    // Check our cache first
                    if (methods.Item2.TryGetValue((IntPtr)methodInst, out var inflatedMethodPointer))
                        return (Il2CppMethodInfo*)inflatedMethodPointer;

                    // Validate the GenericInst structure before reading it
                    // On Linux, memory alignment is strict. Ensure type_argc is sane.
                    if (methodInst->type_argc > 256 || methodInst->type_argv == null)
                        return Original(methodDefinition, classInst, methodInst);

                    var typeArguments = new Type[methodInst->type_argc];
                    for (var i = 0; i < methodInst->type_argc; i++)
                    {
                        var il2cppType = methodInst->type_argv[i];
                        if (il2cppType == null) return Original(methodDefinition, classInst, methodInst);

                        typeArguments[i] = ClassInjector.SystemTypeFromIl2CppType(il2cppType);
                    }

                    var inflatedMethod = methods.Item1.MakeGenericMethod(typeArguments);
                    Logger.Instance.LogTrace("Inflated method: {InflatedMethod}", inflatedMethod.Name);

                    // Use the specific UnityVersionHandler for Unity 6
                    var wrappedMethod = UnityVersionHandler.Wrap(methodDefinition);
                    if (wrappedMethod == null) return Original(methodDefinition, classInst, methodInst);

                    inflatedMethodPointer = (IntPtr)ClassInjector.ConvertMethodInfo(
                        inflatedMethod, UnityVersionHandler.Wrap(wrappedMethod.Class));

                    // Cache the result to prevent recalculating next time
                    methods.Item2.Add((IntPtr)methodInst, inflatedMethodPointer);

                    return (Il2CppMethodInfo*)inflatedMethodPointer;
                }
            }
            catch (Exception ex)
            {
                // CRITICAL: On Linux, an unhandled exception in a hook = SIGSEGV.
                // We must catch and log, then return original.
#if DEBUG
                Logger.Instance.LogError($"[GenericHook] Exception: {ex.Message}");
#endif
            }

            return Original(methodDefinition, classInst, methodInst);
        }

        public override IntPtr FindTargetMethod()
        {
            var getVirtualMethodAPI = InjectorHelpers.GetIl2CppExport(nameof(IL2CPP.il2cpp_object_get_virtual_method));
            if (getVirtualMethodAPI == IntPtr.Zero) return IntPtr.Zero;

            // Follow the export thunk's jump into the actual function body (Object::GetVirtualMethod)
            var getVirtualMethod = XrefScannerLowLevel.JumpTargets(getVirtualMethodAPI).FirstOrDefault();
            if (getVirtualMethod == IntPtr.Zero) return IntPtr.Zero;

            if (XrefScannerLowLevel.IsArm64)
                return FindTargetMethodArm64(getVirtualMethod);

            // We are looking for the call to GetGenericVirtualMethod
            var xrefs = XrefScannerLowLevel.JumpTargets(getVirtualMethod).ToArray();
            if (xrefs.Length == 0) return IntPtr.Zero;

            // On Linux Unity 6, it's usually the LAST jump before the end of the function
            IntPtr getGenericVirtualMethod = xrefs.Last();

            // Now, inside GetGenericVirtualMethod, there is a tail-call (jmp) to GenericMethod::GetMethod
            var finalXrefs = XrefScannerLowLevel.JumpTargets(getGenericVirtualMethod).ToArray();

            if (finalXrefs.Length == 0)
                return IntPtr.Zero;

            IntPtr candidate = finalXrefs.Last();

            // VERIFICATION: On Linux, GenericMethod::GetMethod is a large function.
            // If the address is too close to the caller, it's probably wrong.
#if DEBUG
            Logger.Instance.LogDebug($"[Scanner] Found GenericMethod::GetMethod candidate: 0x{candidate:X}");
#endif

            return candidate;
        }

        // arm64 (Apple Silicon / clang) lays this chain out differently than the x86 codegen the
        // upstream heuristic assumes. Reverse-engineered from BTD6's GameAssembly.dylib:
        //   Object::GetVirtualMethod  --tail-call B-->  GetGenericVirtualMethod
        //   GetGenericVirtualMethod   --BL-->           GenericMethod::GetMethod(Il2CppGenericMethod&)  [1-param worker]
        //   GenericMethod::GetMethod(MethodInfo*, classInst, methodInst)  [3-param, our delegate]  sits
        //     immediately before the 1-param worker and also BL's into it.
        // So: take the body's far tail-call (skipping near local branches and PLT/helper BLs) to reach
        // GetGenericVirtualMethod, follow its first BL to the worker, then walk back to the prologue of
        // the function directly preceding the worker — the 3-param GetMethod that matches our delegate.
        private IntPtr FindTargetMethodArm64(IntPtr getVirtualMethod)
        {
            var bodyBase = (long)getVirtualMethod;
            var bodyTargets = XrefScannerLowLevel.JumpTargetsArm64Tagged(getVirtualMethod).ToArray();

            // GetGenericVirtualMethod is reached via a tail-call (B, not BL) to a *far* address
            // (outside this function's body), distinguishing it from near local branches.
            IntPtr getGenericVirtualMethod = bodyTargets
                .Where(t => !t.isCall && ((long)t.target < bodyBase || (long)t.target > bodyBase + 0x2000))
                .Select(t => t.target)
                .LastOrDefault();
            if (getGenericVirtualMethod == IntPtr.Zero) return IntPtr.Zero;

            // Inside GetGenericVirtualMethod, the first real call (BL) is the 1-param GetMethod worker.
            IntPtr worker = XrefScannerLowLevel.JumpTargetsArm64Tagged(getGenericVirtualMethod)
                .Where(t => t.isCall)
                .Select(t => t.target)
                .FirstOrDefault();
            if (worker == IntPtr.Zero) return IntPtr.Zero;

            // The 3-param GenericMethod::GetMethod (our delegate's ABI) is the function immediately
            // preceding the worker; recover its entry by walking back from just before the worker.
            IntPtr candidate = XrefScannerLowLevel.Arm64FunctionStart((IntPtr)((long)worker - 4));
            Logger.Instance.LogWarning("[arm64] GenericMethod::GetMethod ggvm=0x{G} worker=0x{W} target=0x{T}",
                ((long)getGenericVirtualMethod).ToString("X"), ((long)worker).ToString("X"), ((long)candidate).ToString("X"));
            return candidate;
        }
    }
}
