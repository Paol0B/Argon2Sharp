using System;
using System.Runtime.InteropServices;

namespace Argon2Sharp.Core
{
    internal static class Argon2Native
    {
        private const string LibName = "argon2_sharp_core";

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "argon2_hash")]
        public static extern unsafe int Hash(
            byte* pass, nuint passLen,
            byte* salt, nuint saltLen,
            byte* secret, nuint secretLen,
            byte* associatedData, nuint associatedDataLen,
            uint iterations,
            uint memory,
            uint parallelism,
            byte* outHash,
            nuint hashLen,
            uint typeId,
            uint version
        );
    }
}
