using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Argon2Sharp.Core;

/// <summary>
/// Core Argon2 block operations - compression function and permutations.
/// Implements the core algorithm as specified in RFC 9106.
/// Optimized for maximum performance with SIMD intrinsics.
/// </summary>
internal static class Argon2Core
{
    public const int BlockSize = 1024; // 1024 bytes = 128 64-bit words
    public const int QwordsInBlock = BlockSize / 8; // 128 qwords
    public const int SyncPoints = 4;

    /// <summary>
    /// Argon2 compression function G - optimized inline version.
    /// Operates on two 1024-byte blocks and produces one 1024-byte block.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CompressionG(Span<ulong> block, int a, int b, int c, int d)
    {
        ulong va = block[a];
        ulong vb = block[b];
        ulong vc = block[c];
        ulong vd = block[d];

        // Fused multiply-add operations with inline multiplication
        va += vb + ((va & 0xFFFFFFFFUL) * (vb & 0xFFFFFFFFUL) << 1);
        vd = ulong.RotateRight(vd ^ va, 32);
        vc += vd + ((vc & 0xFFFFFFFFUL) * (vd & 0xFFFFFFFFUL) << 1);
        vb = ulong.RotateRight(vb ^ vc, 24);
        va += vb + ((va & 0xFFFFFFFFUL) * (vb & 0xFFFFFFFFUL) << 1);
        vd = ulong.RotateRight(vd ^ va, 16);
        vc += vd + ((vc & 0xFFFFFFFFUL) * (vd & 0xFFFFFFFFUL) << 1);
        vb = ulong.RotateRight(vb ^ vc, 63);

        block[a] = va;
        block[b] = vb;
        block[c] = vc;
        block[d] = vd;
    }

    /// <summary>
    /// P permutation - applies column and row operations.
    /// Fully unrolled for maximum performance.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void PermutationP(Span<ulong> block)
    {
        // 1. Apply Blake2b round function to each of the 8 rows
        // Row 0
        CompressionG(block, 0, 4, 8, 12);
        CompressionG(block, 1, 5, 9, 13);
        CompressionG(block, 2, 6, 10, 14);
        CompressionG(block, 3, 7, 11, 15);
        CompressionG(block, 0, 5, 10, 15);
        CompressionG(block, 1, 6, 11, 12);
        CompressionG(block, 2, 7, 8, 13);
        CompressionG(block, 3, 4, 9, 14);

        // Row 1
        CompressionG(block, 16, 20, 24, 28);
        CompressionG(block, 17, 21, 25, 29);
        CompressionG(block, 18, 22, 26, 30);
        CompressionG(block, 19, 23, 27, 31);
        CompressionG(block, 16, 21, 26, 31);
        CompressionG(block, 17, 22, 27, 28);
        CompressionG(block, 18, 23, 24, 29);
        CompressionG(block, 19, 20, 25, 30);

        // Row 2
        CompressionG(block, 32, 36, 40, 44);
        CompressionG(block, 33, 37, 41, 45);
        CompressionG(block, 34, 38, 42, 46);
        CompressionG(block, 35, 39, 43, 47);
        CompressionG(block, 32, 37, 42, 47);
        CompressionG(block, 33, 38, 43, 44);
        CompressionG(block, 34, 39, 40, 45);
        CompressionG(block, 35, 36, 41, 46);

        // Row 3
        CompressionG(block, 48, 52, 56, 60);
        CompressionG(block, 49, 53, 57, 61);
        CompressionG(block, 50, 54, 58, 62);
        CompressionG(block, 51, 55, 59, 63);
        CompressionG(block, 48, 53, 58, 63);
        CompressionG(block, 49, 54, 59, 60);
        CompressionG(block, 50, 55, 56, 61);
        CompressionG(block, 51, 52, 57, 62);

        // Row 4
        CompressionG(block, 64, 68, 72, 76);
        CompressionG(block, 65, 69, 73, 77);
        CompressionG(block, 66, 70, 74, 78);
        CompressionG(block, 67, 71, 75, 79);
        CompressionG(block, 64, 69, 74, 79);
        CompressionG(block, 65, 70, 75, 76);
        CompressionG(block, 66, 71, 72, 77);
        CompressionG(block, 67, 68, 73, 78);

        // Row 5
        CompressionG(block, 80, 84, 88, 92);
        CompressionG(block, 81, 85, 89, 93);
        CompressionG(block, 82, 86, 90, 94);
        CompressionG(block, 83, 87, 91, 95);
        CompressionG(block, 80, 85, 90, 95);
        CompressionG(block, 81, 86, 91, 92);
        CompressionG(block, 82, 87, 88, 93);
        CompressionG(block, 83, 84, 89, 94);

        // Row 6
        CompressionG(block, 96, 100, 104, 108);
        CompressionG(block, 97, 101, 105, 109);
        CompressionG(block, 98, 102, 106, 110);
        CompressionG(block, 99, 103, 107, 111);
        CompressionG(block, 96, 101, 106, 111);
        CompressionG(block, 97, 102, 107, 108);
        CompressionG(block, 98, 103, 104, 109);
        CompressionG(block, 99, 100, 105, 110);

        // Row 7
        CompressionG(block, 112, 116, 120, 124);
        CompressionG(block, 113, 117, 121, 125);
        CompressionG(block, 114, 118, 122, 126);
        CompressionG(block, 115, 119, 123, 127);
        CompressionG(block, 112, 117, 122, 127);
        CompressionG(block, 113, 118, 123, 124);
        CompressionG(block, 114, 119, 120, 125);
        CompressionG(block, 115, 116, 121, 126);

        // 2. Apply Blake2b round function to each of the 8 column-pairs
        // Column-Pair 0
        CompressionG(block, 0, 32, 64, 96);
        CompressionG(block, 1, 33, 65, 97);
        CompressionG(block, 16, 48, 80, 112);
        CompressionG(block, 17, 49, 81, 113);
        CompressionG(block, 0, 33, 80, 113);
        CompressionG(block, 1, 48, 81, 96);
        CompressionG(block, 16, 49, 64, 97);
        CompressionG(block, 17, 32, 65, 112);

        // Column-Pair 1
        CompressionG(block, 2, 34, 66, 98);
        CompressionG(block, 3, 35, 67, 99);
        CompressionG(block, 18, 50, 82, 114);
        CompressionG(block, 19, 51, 83, 115);
        CompressionG(block, 2, 35, 82, 115);
        CompressionG(block, 3, 50, 83, 98);
        CompressionG(block, 18, 51, 66, 99);
        CompressionG(block, 19, 34, 67, 114);

        // Column-Pair 2
        CompressionG(block, 4, 36, 68, 100);
        CompressionG(block, 5, 37, 69, 101);
        CompressionG(block, 20, 52, 84, 116);
        CompressionG(block, 21, 53, 85, 117);
        CompressionG(block, 4, 37, 84, 117);
        CompressionG(block, 5, 52, 85, 100);
        CompressionG(block, 20, 53, 68, 101);
        CompressionG(block, 21, 36, 69, 116);

        // Column-Pair 3
        CompressionG(block, 6, 38, 70, 102);
        CompressionG(block, 7, 39, 71, 103);
        CompressionG(block, 22, 54, 86, 118);
        CompressionG(block, 23, 55, 87, 119);
        CompressionG(block, 6, 39, 86, 119);
        CompressionG(block, 7, 54, 87, 102);
        CompressionG(block, 22, 55, 70, 103);
        CompressionG(block, 23, 38, 71, 118);

        // Column-Pair 4
        CompressionG(block, 8, 40, 72, 104);
        CompressionG(block, 9, 41, 73, 105);
        CompressionG(block, 24, 56, 88, 120);
        CompressionG(block, 25, 57, 89, 121);
        CompressionG(block, 8, 41, 88, 121);
        CompressionG(block, 9, 56, 89, 104);
        CompressionG(block, 24, 57, 72, 105);
        CompressionG(block, 25, 40, 73, 120);

        // Column-Pair 5
        CompressionG(block, 10, 42, 74, 106);
        CompressionG(block, 11, 43, 75, 107);
        CompressionG(block, 26, 58, 90, 122);
        CompressionG(block, 27, 59, 91, 123);
        CompressionG(block, 10, 43, 90, 123);
        CompressionG(block, 11, 58, 91, 106);
        CompressionG(block, 26, 59, 74, 107);
        CompressionG(block, 27, 42, 75, 122);

        // Column-Pair 6
        CompressionG(block, 12, 44, 76, 108);
        CompressionG(block, 13, 45, 77, 109);
        CompressionG(block, 28, 60, 92, 124);
        CompressionG(block, 29, 61, 93, 125);
        CompressionG(block, 12, 45, 92, 125);
        CompressionG(block, 13, 60, 93, 108);
        CompressionG(block, 28, 61, 76, 109);
        CompressionG(block, 29, 44, 77, 124);

        // Column-Pair 7
        CompressionG(block, 14, 46, 78, 110);
        CompressionG(block, 15, 47, 79, 111);
        CompressionG(block, 30, 62, 94, 126);
        CompressionG(block, 31, 63, 95, 127);
        CompressionG(block, 14, 47, 94, 127);
        CompressionG(block, 15, 62, 95, 110);
        CompressionG(block, 30, 63, 78, 111);
        CompressionG(block, 31, 46, 79, 126);
    }

    /// <summary>
    /// Argon2 block compression function - SIMD optimized.
    /// Combines two blocks X and Y into a result block using XOR and permutation.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void FillBlock(ReadOnlySpan<ulong> prevBlock, ReadOnlySpan<ulong> refBlock, Span<ulong> nextBlock)
    {
        FillBlock(prevBlock, refBlock, nextBlock, withXor: false);
    }

    /// <summary>
    /// Argon2 block compression function.
    /// When <paramref name="withXor"/> is true (pass &gt; 0 in Argon2 v1.3), XORs the result into <paramref name="nextBlock"/>.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void FillBlock(ReadOnlySpan<ulong> prevBlock, ReadOnlySpan<ulong> refBlock, Span<ulong> nextBlock, bool withXor)
    {
        // Use Vector<ulong> for SIMD operations when available
        if (Vector.IsHardwareAccelerated && Vector<ulong>.Count >= 2)
        {
            FillBlockSimd(prevBlock, refBlock, nextBlock, withXor);
        }
        else
        {
            FillBlockScalar(prevBlock, refBlock, nextBlock, withXor);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static void FillBlockSimd(ReadOnlySpan<ulong> prevBlock, ReadOnlySpan<ulong> refBlock, Span<ulong> nextBlock, bool withXor)
    {
        Span<ulong> r = stackalloc ulong[QwordsInBlock];
        Span<ulong> z = stackalloc ulong[QwordsInBlock];

        int vectorSize = Vector<ulong>.Count;
        int vectorizedLength = QwordsInBlock - (QwordsInBlock % vectorSize);

        // R = X XOR Y (vectorized)
        for (int i = 0; i < vectorizedLength; i += vectorSize)
        {
            var prevVec = new Vector<ulong>(prevBlock.Slice(i));
            var refVec = new Vector<ulong>(refBlock.Slice(i));
            (prevVec ^ refVec).CopyTo(r.Slice(i));
        }
        for (int i = vectorizedLength; i < QwordsInBlock; i++)
        {
            r[i] = prevBlock[i] ^ refBlock[i];
        }

        r.CopyTo(z);

        // Apply P permutation
        PermutationP(z);

        // Z = prev XOR ref XOR P(R) (vectorized)
        for (int i = 0; i < vectorizedLength; i += vectorSize)
        {
            var prevVec = new Vector<ulong>(prevBlock.Slice(i));
            var refVec = new Vector<ulong>(refBlock.Slice(i));
            var zVec = new Vector<ulong>(z.Slice(i));

            var outVec = prevVec ^ refVec ^ zVec;
            if (withXor)
            {
                var nextVec = new Vector<ulong>(nextBlock.Slice(i));
                (nextVec ^ outVec).CopyTo(nextBlock.Slice(i));
            }
            else
            {
                outVec.CopyTo(nextBlock.Slice(i));
            }
        }
        for (int i = vectorizedLength; i < QwordsInBlock; i++)
        {
            ulong outWord = prevBlock[i] ^ refBlock[i] ^ z[i];
            nextBlock[i] = withXor ? (nextBlock[i] ^ outWord) : outWord;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private static void FillBlockScalar(ReadOnlySpan<ulong> prevBlock, ReadOnlySpan<ulong> refBlock, Span<ulong> nextBlock, bool withXor)
    {
        Span<ulong> r = stackalloc ulong[QwordsInBlock];
        Span<ulong> z = stackalloc ulong[QwordsInBlock];

        // R = X XOR Y - unrolled by 8
        int i = 0;
        for (; i + 8 <= QwordsInBlock; i += 8)
        {
            r[i] = prevBlock[i] ^ refBlock[i];
            r[i + 1] = prevBlock[i + 1] ^ refBlock[i + 1];
            r[i + 2] = prevBlock[i + 2] ^ refBlock[i + 2];
            r[i + 3] = prevBlock[i + 3] ^ refBlock[i + 3];
            r[i + 4] = prevBlock[i + 4] ^ refBlock[i + 4];
            r[i + 5] = prevBlock[i + 5] ^ refBlock[i + 5];
            r[i + 6] = prevBlock[i + 6] ^ refBlock[i + 6];
            r[i + 7] = prevBlock[i + 7] ^ refBlock[i + 7];
        }
        for (; i < QwordsInBlock; i++)
        {
            r[i] = prevBlock[i] ^ refBlock[i];
        }

        r.CopyTo(z);

        // Apply P permutation
        PermutationP(z);

        // Z = prev XOR ref XOR P(R) - unrolled by 8
        i = 0;
        for (; i + 8 <= QwordsInBlock; i += 8)
        {
            ulong o0 = prevBlock[i] ^ refBlock[i] ^ z[i];
            ulong o1 = prevBlock[i + 1] ^ refBlock[i + 1] ^ z[i + 1];
            ulong o2 = prevBlock[i + 2] ^ refBlock[i + 2] ^ z[i + 2];
            ulong o3 = prevBlock[i + 3] ^ refBlock[i + 3] ^ z[i + 3];
            ulong o4 = prevBlock[i + 4] ^ refBlock[i + 4] ^ z[i + 4];
            ulong o5 = prevBlock[i + 5] ^ refBlock[i + 5] ^ z[i + 5];
            ulong o6 = prevBlock[i + 6] ^ refBlock[i + 6] ^ z[i + 6];
            ulong o7 = prevBlock[i + 7] ^ refBlock[i + 7] ^ z[i + 7];

            if (withXor)
            {
                nextBlock[i] ^= o0;
                nextBlock[i + 1] ^= o1;
                nextBlock[i + 2] ^= o2;
                nextBlock[i + 3] ^= o3;
                nextBlock[i + 4] ^= o4;
                nextBlock[i + 5] ^= o5;
                nextBlock[i + 6] ^= o6;
                nextBlock[i + 7] ^= o7;
            }
            else
            {
                nextBlock[i] = o0;
                nextBlock[i + 1] = o1;
                nextBlock[i + 2] = o2;
                nextBlock[i + 3] = o3;
                nextBlock[i + 4] = o4;
                nextBlock[i + 5] = o5;
                nextBlock[i + 6] = o6;
                nextBlock[i + 7] = o7;
            }
        }
        for (; i < QwordsInBlock; i++)
        {
            ulong outWord = prevBlock[i] ^ refBlock[i] ^ z[i];
            nextBlock[i] = withXor ? (nextBlock[i] ^ outWord) : outWord;
        }
    }

    /// <summary>
    /// XOR two blocks together - SIMD optimized.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static void XorBlock(ReadOnlySpan<ulong> source, Span<ulong> destination)
    {
        if (Vector.IsHardwareAccelerated && Vector<ulong>.Count >= 2)
        {
            int vectorSize = Vector<ulong>.Count;
            int vectorizedLength = QwordsInBlock - (QwordsInBlock % vectorSize);

            for (int i = 0; i < vectorizedLength; i += vectorSize)
            {
                var srcVec = new Vector<ulong>(source.Slice(i));
                var dstVec = new Vector<ulong>(destination.Slice(i));
                (srcVec ^ dstVec).CopyTo(destination.Slice(i));
            }
            for (int i = vectorizedLength; i < QwordsInBlock; i++)
            {
                destination[i] ^= source[i];
            }
        }
        else
        {
            // Unrolled scalar version
            int i = 0;
            for (; i + 8 <= QwordsInBlock; i += 8)
            {
                destination[i] ^= source[i];
                destination[i + 1] ^= source[i + 1];
                destination[i + 2] ^= source[i + 2];
                destination[i + 3] ^= source[i + 3];
                destination[i + 4] ^= source[i + 4];
                destination[i + 5] ^= source[i + 5];
                destination[i + 6] ^= source[i + 6];
                destination[i + 7] ^= source[i + 7];
            }
            for (; i < QwordsInBlock; i++)
            {
                destination[i] ^= source[i];
            }
        }
    }

    /// <summary>
    /// Copy a block.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CopyBlock(ReadOnlySpan<ulong> source, Span<ulong> destination)
    {
        source.CopyTo(destination);
    }

    /// <summary>
    /// Convert byte array to ulong array (little-endian).
    /// Uses MemoryMarshal for zero-copy on little-endian systems.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void BytesToQwords(ReadOnlySpan<byte> bytes, Span<ulong> qwords)
    {
        if (BitConverter.IsLittleEndian)
        {
            // Zero-copy cast on little-endian systems
            MemoryMarshal.Cast<byte, ulong>(bytes).CopyTo(qwords);
        }
        else
        {
            // Fallback for big-endian systems
            for (int i = 0; i < qwords.Length; i++)
            {
                qwords[i] = BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(i * 8, 8));
            }
        }
    }

    /// <summary>
    /// Convert ulong array to byte array (little-endian).
    /// Uses MemoryMarshal for zero-copy on little-endian systems.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void QwordsToBytes(ReadOnlySpan<ulong> qwords, Span<byte> bytes)
    {
        if (BitConverter.IsLittleEndian)
        {
            // Zero-copy cast on little-endian systems
            MemoryMarshal.AsBytes(qwords).CopyTo(bytes);
        }
        else
        {
            // Fallback for big-endian systems
            for (int i = 0; i < qwords.Length; i++)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.Slice(i * 8, 8), qwords[i]);
            }
        }
    }
}
