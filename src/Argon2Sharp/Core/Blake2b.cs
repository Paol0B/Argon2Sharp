using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Argon2Sharp.Core;

/// <summary>
/// Pure C# implementation of Blake2b-512 hash function used internally by Argon2.
/// Based on RFC 7693 specification. Highly optimized for performance.
/// </summary>
internal static class Blake2b
{
    private const int BlockSizeInBytes = 128;
    private const int HashSizeInBytes = 64;

    // Blake2b IV constants - stored as static readonly for JIT optimization
    private static readonly ulong[] IVArray =
    [
        0x6A09E667F3BCC908UL, 0xBB67AE8584CAA73BUL,
        0x3C6EF372FE94F82BUL, 0xA54FF53A5F1D36F1UL,
        0x510E527FADE682D1UL, 0x9B05688C2B3E6C1FUL,
        0x1F83D9ABFB41BD6BUL, 0x5BE0CD19137E2179UL
    ];

    private static ReadOnlySpan<ulong> IV => IVArray;

    // Blake2b sigma permutation table - compile-time constant
    private static ReadOnlySpan<byte> Sigma =>
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
        11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
        7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
        9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
        2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
        12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
        13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
        6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
        10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
    ];

    /// <summary>
    /// Computes Blake2b-512 hash of the input data.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void Hash(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (output.Length != HashSizeInBytes)
            throw new ArgumentException($"Output buffer must be {HashSizeInBytes} bytes", nameof(output));

        Span<ulong> h = stackalloc ulong[8];
        IV.CopyTo(h);
        h[0] ^= 0x01010000UL ^ (uint)HashSizeInBytes;

        Span<ulong> m = stackalloc ulong[16];
        ulong t0 = 0, t1 = 0;
        int remaining = input.Length;
        int offset = 0;

        while (remaining > BlockSizeInBytes)
        {
            t0 += BlockSizeInBytes;
            if (t0 < BlockSizeInBytes)
                t1++;

            LoadMessage(input.Slice(offset, BlockSizeInBytes), m);
            Compress(h, m, t0, t1, false);

            offset += BlockSizeInBytes;
            remaining -= BlockSizeInBytes;
        }

        // Final block
        t0 += (uint)remaining;
        if (t0 < (ulong)remaining)
            t1++;

        Span<byte> lastBlock = stackalloc byte[BlockSizeInBytes];
        input.Slice(offset, remaining).CopyTo(lastBlock);
        lastBlock.Slice(remaining).Clear();

        LoadMessage(lastBlock, m);
        Compress(h, m, t0, t1, true);

        // Output hash - optimized for little-endian
        if (BitConverter.IsLittleEndian)
        {
            MemoryMarshal.AsBytes(h).CopyTo(output);
        }
        else
        {
            for (int i = 0; i < 8; i++)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(output.Slice(i * 8, 8), h[i]);
            }
        }
    }

    /// <summary>
    /// Blake2b long hash function for Argon2 - produces variable-length output.
    /// Optimized for common Argon2 block size (1024 bytes).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void LongHash(ReadOnlySpan<byte> input, Span<byte> output)
    {
        int outLen = output.Length;

        if (outLen <= HashSizeInBytes)
        {
            // For short output, hash with length prefix
            Span<byte> prefixedInput = stackalloc byte[input.Length + 4];
            BinaryPrimitives.WriteUInt32LittleEndian(prefixedInput, (uint)outLen);
            input.CopyTo(prefixedInput.Slice(4));
            
            Span<byte> fullHash = stackalloc byte[HashSizeInBytes];
            Hash(prefixedInput, fullHash);
            fullHash.Slice(0, outLen).CopyTo(output);
            return;
        }

        // For longer output, use the variable-length hash construction
        Span<byte> firstBlock = stackalloc byte[input.Length + 4];
        BinaryPrimitives.WriteUInt32LittleEndian(firstBlock, (uint)outLen);
        input.CopyTo(firstBlock.Slice(4));

        Span<byte> hash = stackalloc byte[HashSizeInBytes];
        Hash(firstBlock, hash);

        // First 32 bytes (or half of hash size)
        hash.Slice(0, HashSizeInBytes / 2).CopyTo(output);
        int pos = HashSizeInBytes / 2;
        int remaining = outLen - (HashSizeInBytes / 2);

        // Subsequent blocks
        while (remaining > HashSizeInBytes / 2)
        {
            Hash(hash, hash);
            hash.Slice(0, HashSizeInBytes / 2).CopyTo(output.Slice(pos));
            pos += HashSizeInBytes / 2;
            remaining -= HashSizeInBytes / 2;
        }

        // Final block
        Hash(hash, hash);
        hash.Slice(0, remaining).CopyTo(output.Slice(pos));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void LoadMessage(ReadOnlySpan<byte> block, Span<ulong> m)
    {
        if (BitConverter.IsLittleEndian)
        {
            MemoryMarshal.Cast<byte, ulong>(block).CopyTo(m);
        }
        else
        {
            for (int i = 0; i < 16; i++)
            {
                m[i] = BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(i * 8, 8));
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static void Compress(Span<ulong> h, Span<ulong> m, ulong t0, ulong t1, bool isLastBlock)
    {
        // Use local variables for better register allocation
        ulong v0 = h[0], v1 = h[1], v2 = h[2], v3 = h[3];
        ulong v4 = h[4], v5 = h[5], v6 = h[6], v7 = h[7];
        ulong v8 = IVArray[0], v9 = IVArray[1], v10 = IVArray[2], v11 = IVArray[3];
        ulong v12 = IVArray[4] ^ t0, v13 = IVArray[5] ^ t1;
        ulong v14 = IVArray[6], v15 = IVArray[7];

        if (isLastBlock)
            v14 = ~v14;

        // Cache message words
        ulong m0 = m[0], m1 = m[1], m2 = m[2], m3 = m[3];
        ulong m4 = m[4], m5 = m[5], m6 = m[6], m7 = m[7];
        ulong m8 = m[8], m9 = m[9], m10 = m[10], m11 = m[11];
        ulong m12 = m[12], m13 = m[13], m14 = m[14], m15 = m[15];

        // Round 0
        GInline(ref v0, ref v4, ref v8, ref v12, m0, m1);
        GInline(ref v1, ref v5, ref v9, ref v13, m2, m3);
        GInline(ref v2, ref v6, ref v10, ref v14, m4, m5);
        GInline(ref v3, ref v7, ref v11, ref v15, m6, m7);
        GInline(ref v0, ref v5, ref v10, ref v15, m8, m9);
        GInline(ref v1, ref v6, ref v11, ref v12, m10, m11);
        GInline(ref v2, ref v7, ref v8, ref v13, m12, m13);
        GInline(ref v3, ref v4, ref v9, ref v14, m14, m15);

        // Round 1
        GInline(ref v0, ref v4, ref v8, ref v12, m14, m10);
        GInline(ref v1, ref v5, ref v9, ref v13, m4, m8);
        GInline(ref v2, ref v6, ref v10, ref v14, m9, m15);
        GInline(ref v3, ref v7, ref v11, ref v15, m13, m6);
        GInline(ref v0, ref v5, ref v10, ref v15, m1, m12);
        GInline(ref v1, ref v6, ref v11, ref v12, m0, m2);
        GInline(ref v2, ref v7, ref v8, ref v13, m11, m7);
        GInline(ref v3, ref v4, ref v9, ref v14, m5, m3);

        // Round 2
        GInline(ref v0, ref v4, ref v8, ref v12, m11, m8);
        GInline(ref v1, ref v5, ref v9, ref v13, m12, m0);
        GInline(ref v2, ref v6, ref v10, ref v14, m5, m2);
        GInline(ref v3, ref v7, ref v11, ref v15, m15, m13);
        GInline(ref v0, ref v5, ref v10, ref v15, m10, m14);
        GInline(ref v1, ref v6, ref v11, ref v12, m3, m6);
        GInline(ref v2, ref v7, ref v8, ref v13, m7, m1);
        GInline(ref v3, ref v4, ref v9, ref v14, m9, m4);

        // Round 3
        GInline(ref v0, ref v4, ref v8, ref v12, m7, m9);
        GInline(ref v1, ref v5, ref v9, ref v13, m3, m1);
        GInline(ref v2, ref v6, ref v10, ref v14, m13, m12);
        GInline(ref v3, ref v7, ref v11, ref v15, m11, m14);
        GInline(ref v0, ref v5, ref v10, ref v15, m2, m6);
        GInline(ref v1, ref v6, ref v11, ref v12, m5, m10);
        GInline(ref v2, ref v7, ref v8, ref v13, m4, m0);
        GInline(ref v3, ref v4, ref v9, ref v14, m15, m8);

        // Round 4
        GInline(ref v0, ref v4, ref v8, ref v12, m9, m0);
        GInline(ref v1, ref v5, ref v9, ref v13, m5, m7);
        GInline(ref v2, ref v6, ref v10, ref v14, m2, m4);
        GInline(ref v3, ref v7, ref v11, ref v15, m10, m15);
        GInline(ref v0, ref v5, ref v10, ref v15, m14, m1);
        GInline(ref v1, ref v6, ref v11, ref v12, m11, m12);
        GInline(ref v2, ref v7, ref v8, ref v13, m6, m8);
        GInline(ref v3, ref v4, ref v9, ref v14, m3, m13);

        // Round 5
        GInline(ref v0, ref v4, ref v8, ref v12, m2, m12);
        GInline(ref v1, ref v5, ref v9, ref v13, m6, m10);
        GInline(ref v2, ref v6, ref v10, ref v14, m0, m11);
        GInline(ref v3, ref v7, ref v11, ref v15, m8, m3);
        GInline(ref v0, ref v5, ref v10, ref v15, m4, m13);
        GInline(ref v1, ref v6, ref v11, ref v12, m7, m5);
        GInline(ref v2, ref v7, ref v8, ref v13, m15, m14);
        GInline(ref v3, ref v4, ref v9, ref v14, m1, m9);

        // Round 6
        GInline(ref v0, ref v4, ref v8, ref v12, m12, m5);
        GInline(ref v1, ref v5, ref v9, ref v13, m1, m15);
        GInline(ref v2, ref v6, ref v10, ref v14, m14, m13);
        GInline(ref v3, ref v7, ref v11, ref v15, m4, m10);
        GInline(ref v0, ref v5, ref v10, ref v15, m0, m7);
        GInline(ref v1, ref v6, ref v11, ref v12, m6, m3);
        GInline(ref v2, ref v7, ref v8, ref v13, m9, m2);
        GInline(ref v3, ref v4, ref v9, ref v14, m8, m11);

        // Round 7
        GInline(ref v0, ref v4, ref v8, ref v12, m13, m11);
        GInline(ref v1, ref v5, ref v9, ref v13, m7, m14);
        GInline(ref v2, ref v6, ref v10, ref v14, m12, m1);
        GInline(ref v3, ref v7, ref v11, ref v15, m3, m9);
        GInline(ref v0, ref v5, ref v10, ref v15, m5, m0);
        GInline(ref v1, ref v6, ref v11, ref v12, m15, m4);
        GInline(ref v2, ref v7, ref v8, ref v13, m8, m6);
        GInline(ref v3, ref v4, ref v9, ref v14, m2, m10);

        // Round 8
        GInline(ref v0, ref v4, ref v8, ref v12, m6, m15);
        GInline(ref v1, ref v5, ref v9, ref v13, m14, m9);
        GInline(ref v2, ref v6, ref v10, ref v14, m11, m3);
        GInline(ref v3, ref v7, ref v11, ref v15, m0, m8);
        GInline(ref v0, ref v5, ref v10, ref v15, m12, m2);
        GInline(ref v1, ref v6, ref v11, ref v12, m13, m7);
        GInline(ref v2, ref v7, ref v8, ref v13, m1, m4);
        GInline(ref v3, ref v4, ref v9, ref v14, m10, m5);

        // Round 9
        GInline(ref v0, ref v4, ref v8, ref v12, m10, m2);
        GInline(ref v1, ref v5, ref v9, ref v13, m8, m4);
        GInline(ref v2, ref v6, ref v10, ref v14, m7, m6);
        GInline(ref v3, ref v7, ref v11, ref v15, m1, m5);
        GInline(ref v0, ref v5, ref v10, ref v15, m15, m11);
        GInline(ref v1, ref v6, ref v11, ref v12, m9, m14);
        GInline(ref v2, ref v7, ref v8, ref v13, m3, m12);
        GInline(ref v3, ref v4, ref v9, ref v14, m13, m0);

        // Round 10
        GInline(ref v0, ref v4, ref v8, ref v12, m0, m1);
        GInline(ref v1, ref v5, ref v9, ref v13, m2, m3);
        GInline(ref v2, ref v6, ref v10, ref v14, m4, m5);
        GInline(ref v3, ref v7, ref v11, ref v15, m6, m7);
        GInline(ref v0, ref v5, ref v10, ref v15, m8, m9);
        GInline(ref v1, ref v6, ref v11, ref v12, m10, m11);
        GInline(ref v2, ref v7, ref v8, ref v13, m12, m13);
        GInline(ref v3, ref v4, ref v9, ref v14, m14, m15);

        // Round 11
        GInline(ref v0, ref v4, ref v8, ref v12, m14, m10);
        GInline(ref v1, ref v5, ref v9, ref v13, m4, m8);
        GInline(ref v2, ref v6, ref v10, ref v14, m9, m15);
        GInline(ref v3, ref v7, ref v11, ref v15, m13, m6);
        GInline(ref v0, ref v5, ref v10, ref v15, m1, m12);
        GInline(ref v1, ref v6, ref v11, ref v12, m0, m2);
        GInline(ref v2, ref v7, ref v8, ref v13, m11, m7);
        GInline(ref v3, ref v4, ref v9, ref v14, m5, m3);

        // Finalize
        h[0] ^= v0 ^ v8;
        h[1] ^= v1 ^ v9;
        h[2] ^= v2 ^ v10;
        h[3] ^= v3 ^ v11;
        h[4] ^= v4 ^ v12;
        h[5] ^= v5 ^ v13;
        h[6] ^= v6 ^ v14;
        h[7] ^= v7 ^ v15;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void GInline(ref ulong a, ref ulong b, ref ulong c, ref ulong d, ulong x, ulong y)
    {
        a += b + x;
        d = ulong.RotateRight(d ^ a, 32);
        c += d;
        b = ulong.RotateRight(b ^ c, 24);
        a += b + y;
        d = ulong.RotateRight(d ^ a, 16);
        c += d;
        b = ulong.RotateRight(b ^ c, 63);
    }
}
