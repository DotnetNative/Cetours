using Cetours.Assembler;
using Cetours.Hooking.Interfaces;

namespace Cetours.Hooking;

public unsafe abstract class Hook
{
    public Hook(void* origin, void* ripped, void* newFunc, HookInnerData data)
    {
        Origin = origin;
        Ripped = ripped;
        New = newFunc;
        Data = data;
    }

    public void* Origin;
    public void* Ripped;
    public void* New;

    public HookInnerData Data;
    public Register JmpRegister => (Data as ICustomJmpRegister).JmpRegister;

    public abstract void Attach();
    public abstract void Detach();
}

public unsafe class RedirectHook : Hook
{
    public RedirectHook(void* origin, void* ripped, void* newFunc, HookInnerData data) : base(origin, ripped, newFunc, data)
    {
        Redirect = JmpRedirect.Create(this, Origin, Ripped);
    }

    public JmpRedirect Redirect;

    public override void Attach() => Redirect.Enable();
    public override void Detach() => Redirect.Disable();
}

public unsafe class AllocationTrampolineHook : Hook
{
    public AllocationTrampolineHook(void* origin, void* ripped, void* newFunc, HookInnerData data) : base(origin, ripped, newFunc, data)
    {
        OrigToNewRedirect = JmpRedirect.Create(this, Origin, newFunc);
        NewToRippedRedirect = JmpRedirect.Create(this, newFunc, Ripped);
        NewToRippedRedirect.Enable();
        RippedMirror = newFunc;
        New = newFunc = (byte*)newFunc + NewToRippedRedirect.Length/*(byte*)newFunc + GetSizeOfJmpAbsoluteX64((data as ICustomJmpRegister).JmpRegister)*/;

        var asm = new ASM(newFunc);
        asm.Copy(origin, OrigToNewRedirect.Length);
        void* newFuncRedirect = asm.CurrentAddr();
        NewToOrigRedirect = JmpRedirect.Create(this, newFuncRedirect, (byte*)origin + OrigToNewRedirect.Length);
        NewToOrigRedirect.Enable();
    }

    public JmpRedirect OrigToNewRedirect, NewToRippedRedirect, NewToOrigRedirect;
    public void* RippedMirror;

    public override void Attach() => OrigToNewRedirect.Enable();
    public override void Detach() => OrigToNewRedirect.Disable();
}