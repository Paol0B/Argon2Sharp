using System.Runtime.InteropServices;

namespace Argon2Sharp.Core;

internal static class Argon2RustBridge
{
    private const string LibraryName = "argon2sharp_rust";

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "argon2_hash")]
    private static extern int Argon2Hash(
        IntPtr password,
        UIntPtr passwordLen,
        IntPtr salt,
        UIntPtr saltLen,
        IntPtr secret,
        UIntPtr secretLen,
        IntPtr ad,
        UIntPtr adLen,
        int iterations,
        int memoryKb,
        int parallelism,
        int hashLen,
        int typeCode,
        int versionCode,
        IntPtr output
    );

    public static void Hash(Argon2Parameters parameters, ReadOnlySpan<byte> password, Span<byte> output)
    {
        unsafe
        {
            fixed (byte* pwdPtr = password)
            fixed (byte* saltPtr = parameters.Salt)
            fixed (byte* secretPtr = parameters.Secret)
            fixed (byte* adPtr = parameters.AssociatedData)
            fixed (byte* outPtr = output)
            {
                int typeCode = parameters.Type switch
                {
                    Argon2Type.Argon2d => 0,
                    Argon2Type.Argon2i => 1,
                    Argon2Type.Argon2id => 2,
                    _ => throw new ArgumentException("Invalid Argon2 type")
                };

                int versionCode = parameters.Version switch
                {
                    Argon2Version.Version10 => 0x10,
                    Argon2Version.Version13 => 0x13,
                    _ => throw new ArgumentException("Invalid Argon2 version")
                };

                int result = Argon2Hash(
                    (IntPtr)pwdPtr,
                    (UIntPtr)password.Length,
                    (IntPtr)saltPtr,
                    (UIntPtr)(parameters.Salt?.Length ?? 0),
                    (IntPtr)secretPtr,
                    (UIntPtr)(parameters.Secret?.Length ?? 0),
                    (IntPtr)adPtr,
                    (UIntPtr)(parameters.AssociatedData?.Length ?? 0),
                    parameters.Iterations,
                    parameters.MemorySizeKB,
                    parameters.Parallelism,
                    parameters.HashLength,
                    typeCode,
                    versionCode,
                    (IntPtr)outPtr
                );

                if (result != 0)
                {
                    throw new InvalidOperationException($"Argon2 Rust implementation failed with error code {result}");
                }
            }
        }
    }
}
