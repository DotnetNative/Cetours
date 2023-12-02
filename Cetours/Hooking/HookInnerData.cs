using Cetours.Assembler;
using Cetours.Hooking.Interfaces;

namespace Cetours.Hooking;
public class HookInnerData : ICustomJmpRegister
{
    public HookInnerData() { }

    public HookInnerData(Register jmpRegister)
    {
        this.jmpRegister = jmpRegister;
    }

    Register jmpRegister = X64Registers.RAX;
    Register ICustomJmpRegister.JmpRegister { get => jmpRegister; set => jmpRegister = value; }
}