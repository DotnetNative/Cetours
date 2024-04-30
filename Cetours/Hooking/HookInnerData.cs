namespace Cetours.Hooking;
public sealed class HookInnerData
{
    public HookInnerData() { }

    public HookInnerData(X64Register jmpRegister)
    {
        JmpRegister = jmpRegister;
    }

    public readonly X64Register JmpRegister = X64Registers.RAX;
}