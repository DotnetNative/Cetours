namespace Cetours.Hooking;
public unsafe abstract class Hook
{
    public Hook(pointer origin, pointer ripped, pointer newFunc, HookInnerData data)
    {
        Origin = origin;
        Ripped = ripped;
        New = newFunc;
        Data = data;
    }

    public readonly pointer Origin;
    public readonly pointer Ripped;
    public readonly HookInnerData Data;

    public pointer New;

    public abstract void Attach();
    public abstract void Detach();
}

public unsafe class RedirectHook : Hook
{
    public RedirectHook(pointer origin, pointer ripped, pointer newFunc, HookInnerData data) : base(origin, ripped, newFunc, data)
        => Redirect = JmpRedirect.Create(this, Origin, Ripped);

    public readonly JmpRedirect Redirect;

    public override void Attach() => Redirect.Enable();
    public override void Detach() => Redirect.Disable();
}

public unsafe class AllocationTrampolineHook : Hook
{
    public AllocationTrampolineHook(pointer origin, pointer ripped, pointer newFunc, HookInnerData data) : base(origin, ripped, newFunc, data)
    {
        OrigToNewRedirect = JmpRedirect.Create(this, Origin, newFunc);
        NewToRippedRedirect = JmpRedirect.Create(this, newFunc, Ripped);
        NewToRippedRedirect.Enable();
        RippedMirror = newFunc;
        New = newFunc = newFunc + NewToRippedRedirect.Length;

        var asm = new ASM(newFunc);
        asm.Copy(origin, OrigToNewRedirect.Length);
        var newFuncRedirect = asm.CurrentAddr();
        NewToOrigRedirect = JmpRedirect.Create(this, newFuncRedirect, (byte*)origin + OrigToNewRedirect.Length);
        NewToOrigRedirect.Enable();
    }

    public readonly JmpRedirect OrigToNewRedirect, NewToRippedRedirect, NewToOrigRedirect;
    public readonly pointer RippedMirror;

    public override void Attach() => OrigToNewRedirect.Enable();
    public override void Detach() => OrigToNewRedirect.Disable();
}