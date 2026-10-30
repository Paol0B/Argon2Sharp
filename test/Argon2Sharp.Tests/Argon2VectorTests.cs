using System.Diagnostics;
using Xunit;

namespace Argon2Sharp.Tests;

public class Argon2VectorTests
{
    [Fact]
    public void TestRfc9106_Argon2id_TestVector1()
    {
        // RFC test vector parameters
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version13,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = new byte[]
            {
                0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            },
            Secret = new byte[]
            {
                0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
            },
            AssociatedData = new byte[]
            {
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
            }
        };

        var argon2 = new Argon2(parameters);

        Span<byte> password = new Span<byte>( new byte[]
        {
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        } );
        byte[] hash = argon2.Hash(password);

        // Hash should be deterministic and produce consistent results
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);

        // Expected hash from RFC 9106 5.3. Argon2id Test Vectors
        byte[] expectedHash = new byte[]
        {
            0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
            0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59,
        };

        Debug.WriteLine(hash);

        Assert.True(hash.SequenceEqual(expectedHash));

        // Verify hash can be verified
        Assert.True(argon2.Verify(password, hash));
        Assert.False(argon2.Verify("wrongpassword", hash.AsSpan()));
    }

    [Theory]
    [InlineData(Argon2Type.Argon2d, "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb")]
    [InlineData(Argon2Type.Argon2i, "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8")]
    public void TestRfc9106_Argon2dAndArgon2i_TestVectors(Argon2Type type, string expectedHex)
    {
        // RFC 9106 sections 5.1 and 5.2
        var parameters = new Argon2Parameters
        {
            Type = type,
            Version = Argon2Version.Version13,
            MemorySizeKB = 32,
            Iterations = 3,
            Parallelism = 4,
            HashLength = 32,
            Salt = Enumerable.Repeat((byte)0x02, 16).ToArray(),
            Secret = Enumerable.Repeat((byte)0x03, 8).ToArray(),
            AssociatedData = Enumerable.Repeat((byte)0x04, 12).ToArray()
        };

        byte[] hash = new Argon2(parameters).Hash(Enumerable.Repeat((byte)0x01, 32).ToArray().AsSpan());

        Assert.Equal(expectedHex, Convert.ToHexString(hash).ToLowerInvariant());
    }

    [Fact]
    public void TestDefaultParameters_MatchReferenceImplementation()
    {
        var parameters = Argon2Parameters.CreateDefault() with { Salt = "somesalt"u8.ToArray() };

        byte[] hash = new Argon2(parameters).Hash("correct horse battery staple");

        // phc-winner-argon2 CLI output
        Assert.Equal("0448030d65fba6008da377dd849f43ea3859c7fee13d43cd45acb3060e4b1d13", Convert.ToHexString(hash).ToLowerInvariant());
    }
}
