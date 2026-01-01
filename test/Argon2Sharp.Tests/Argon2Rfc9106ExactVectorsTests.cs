using System;
using Xunit;
using Xunit.Abstractions;

namespace Argon2Sharp.Tests;

/// <summary>
/// Tests using EXACT test vectors from RFC 9106 Section 5.
/// These tests validate byte-for-byte compatibility with the RFC specification.
/// </summary>
public class Argon2Rfc9106ExactVectorsTests
{
    private readonly ITestOutputHelper _output;

    public Argon2Rfc9106ExactVectorsTests(ITestOutputHelper output)
    {
        _output = output;
    }

    /// <summary>
    /// RFC 9106 Section 5.3 - Argon2id Test Vector
    /// </summary>
    [Fact]
    public void TestRfc9106_Section5_3_Argon2id_ExactTestVector()
    {
        // From RFC 9106 Section 5.3
        // Memory: 32 KiB, Passes: 3, Parallelism: 4 lanes, Tag length: 32 bytes
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version13, // 0x13 = 19
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = new byte[]
            {
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
            },
            Secret = new byte[]
            {
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03
            },
            AssociatedData = new byte[]
            {
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x04, 0x04
            }
        };

        byte[] password = new byte[]
        {
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
        };

        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Expected tag from RFC 9106 Section 5.3
        byte[] expectedHash = new byte[]
        {
            0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c,
            0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
            0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e,
            0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59
        };

        _output.WriteLine("Expected hash: " + BitConverter.ToString(expectedHash).Replace("-", " "));
        _output.WriteLine("Actual hash:   " + BitConverter.ToString(hash).Replace("-", " "));

        Assert.Equal(expectedHash, hash);
    }

    /// <summary>
    /// RFC 9106 Section 5.1 - Argon2d Test Vector
    /// </summary>
    [Fact]
    public void TestRfc9106_Section5_1_Argon2d_ExactTestVector()
    {
        // From RFC 9106 Section 5.1
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2d,
            Version = Argon2Version.Version13,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = new byte[]
            {
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
            },
            Secret = new byte[]
            {
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03
            },
            AssociatedData = new byte[]
            {
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x04, 0x04
            }
        };

        byte[] password = new byte[]
        {
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
        };

        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Expected tag from RFC 9106 Section 5.1
        byte[] expectedHash = new byte[]
        {
            0x51, 0x2b, 0x39, 0x1b, 0x6f, 0x11, 0x62, 0x97,
            0x53, 0x71, 0xd3, 0x09, 0x19, 0x73, 0x42, 0x94,
            0xf8, 0x68, 0xe3, 0xbe, 0x39, 0x84, 0xf3, 0xc1,
            0xa1, 0x3a, 0x4d, 0xb9, 0xfa, 0xbe, 0x4a, 0xcb
        };

        _output.WriteLine("Expected hash: " + BitConverter.ToString(expectedHash).Replace("-", " "));
        _output.WriteLine("Actual hash:   " + BitConverter.ToString(hash).Replace("-", " "));

        Assert.Equal(expectedHash, hash);
    }

    /// <summary>
    /// RFC 9106 Section 5.2 - Argon2i Test Vector
    /// </summary>
    [Fact]
    public void TestRfc9106_Section5_2_Argon2i_ExactTestVector()
    {
        // From RFC 9106 Section 5.2
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2i,
            Version = Argon2Version.Version13,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = new byte[]
            {
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
            },
            Secret = new byte[]
            {
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03
            },
            AssociatedData = new byte[]
            {
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x04, 0x04
            }
        };

        byte[] password = new byte[]
        {
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
        };

        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        // Expected tag from RFC 9106 Section 5.2
        byte[] expectedHash = new byte[]
        {
            0xc8, 0x14, 0xd9, 0xd1, 0xdc, 0x7f, 0x37, 0xaa,
            0x13, 0xf0, 0xd7, 0x7f, 0x24, 0x94, 0xbd, 0xa1,
            0xc8, 0xde, 0x6b, 0x01, 0x6d, 0xd3, 0x88, 0xd2,
            0x99, 0x52, 0xa4, 0xc4, 0x67, 0x2b, 0x6c, 0xe8
        };

        _output.WriteLine("Expected hash: " + BitConverter.ToString(expectedHash).Replace("-", " "));
        _output.WriteLine("Actual hash:   " + BitConverter.ToString(hash).Replace("-", " "));

        Assert.Equal(expectedHash, hash);
    }
}
