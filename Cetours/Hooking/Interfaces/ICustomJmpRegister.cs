using Cetours.Assembler;

namespace Cetours.Hooking.Interfaces;
public interface ICustomJmpRegister
{
    public Register JmpRegister { get; set; }
}