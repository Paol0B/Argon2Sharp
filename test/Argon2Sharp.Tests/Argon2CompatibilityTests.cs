using Xunit;

namespace Argon2Sharp.Tests;

/// <summary>
/// Hashes produced by Argon2Sharp 4.0.2. A failure here means stored hashes no longer verify.
/// </summary>
public class Argon2CompatibilityTests
{
    [Theory]
    [InlineData(Argon2Type.Argon2id, Argon2Version.Version13, 64, 2, 1, 32, 8, 16, 0, 0, "67b5ef38f429955af0fea4321481c9522ff3e991aedbde0b6bdd42bbd5a8bd84")]
    [InlineData(Argon2Type.Argon2d, Argon2Version.Version13, 64, 2, 1, 32, 8, 16, 0, 0, "2435f3293bb084574d66e64df8a67dd00cf92d15145061cdaef31ff567c5e3a7")]
    [InlineData(Argon2Type.Argon2i, Argon2Version.Version13, 64, 2, 1, 32, 8, 16, 0, 0, "c921a500a14f7f6ca924b882acf427cde3191b3ab547ba9d55e5510aed835d07")]
    [InlineData(Argon2Type.Argon2id, Argon2Version.Version10, 64, 2, 1, 32, 8, 16, 0, 0, "fd9d10a4eaa2e6892fa3434dab69c08355ddd5325e710d81462c1fcb5ef18452")]
    [InlineData(Argon2Type.Argon2d, Argon2Version.Version10, 64, 2, 1, 32, 8, 16, 0, 0, "5f984ee259afc6e0efc37f9ba690c9cce73886b42ae004f9eb3cdcbc7ebcf2cd")]
    [InlineData(Argon2Type.Argon2i, Argon2Version.Version10, 64, 2, 1, 32, 8, 16, 0, 0, "976b4cf6902e547a8bf0d300b2906bd768b06bbdccde273c5ee837986854939e")]
    [InlineData(Argon2Type.Argon2id, Argon2Version.Version13, 100, 1, 3, 32, 8, 16, 0, 0, "29339e7e830dbfb85033913cd3d261226af17ee9193079555e5b96baf890e27c")]
    [InlineData(Argon2Type.Argon2id, Argon2Version.Version13, 256, 2, 8, 32, 8, 16, 0, 0, "5ec4843e33ca42e4f3118db3ee52c38c958cf1cd33396c66a75173269e9bfad4")]
    [InlineData(Argon2Type.Argon2i, Argon2Version.Version13, 1024, 3, 4, 32, 8, 16, 0, 0, "ff3bcc28005a7ea298693e2305780ceb076d9db967815560133d1d6830ade8a2")]
    [InlineData(Argon2Type.Argon2d, Argon2Version.Version13, 1024, 3, 4, 32, 8, 16, 0, 0, "df97bc8617313fd684a5bc5d0c53f6a4af957e4f7f6dd89f1f6ab2791676d15a")]
    [InlineData(Argon2Type.Argon2id, Argon2Version.Version13, 64, 2, 1, 32, 8, 16, 64, 0, "dcf2901edb7959dbf0f7fcd1088d913a0fc73f8aa090673fd1776c7b59f48e6e")]
    [InlineData(Argon2Type.Argon2id, Argon2Version.Version13, 64, 2, 1, 32, 8, 16, 0, 32, "82b5c8bec35d150624c612d8f3fe12a8735cf9de76ceeb65ec6a8023f72d4399")]
    [InlineData(Argon2Type.Argon2id, Argon2Version.Version13, 64, 2, 1, 32, 8, 16, 0, 33, "6356e545f4a6d14bbb67de3493a47dda8cbef29811f34d4c8729739377b44995")]
    [InlineData(Argon2Type.Argon2id, Argon2Version.Version13, 64, 2, 2, 32, 8, 16, 16, 1000, "e8c8ebc78860f7c199a1090c62dd96eb271c1f8e3f9b893504debd393dd1fe08")]
    [InlineData(Argon2Type.Argon2d, Argon2Version.Version10, 64, 2, 1, 32, 8, 16, 8, 100, "5754a20f808c6e3a6b4f5f360f50a2e369cdec088f9521edddd628843254c853")]
    [InlineData(Argon2Type.Argon2id, Argon2Version.Version13, 64, 2, 1, 4, 8, 16, 0, 0, "dcaacada")]
    [InlineData(Argon2Type.Argon2id, Argon2Version.Version13, 64, 2, 1, 64, 8, 16, 0, 0, "1b679c3728993ad6f79e400a772ff2a076e1f9f710a6fe9a98187812aa70a5e6bee5c76da1f525bfcc42cc9588d523f08c34d89deff43367dc233027213ed54e")]
    [InlineData(Argon2Type.Argon2id, Argon2Version.Version13, 64, 2, 1, 65, 8, 16, 0, 0, "627f6b52ecc467466df73ab4d7356ad29f5e8bc1794f287fcdb2447ff1f3787ba02139f0b660e70a101eb7de806da9ce621bf232d09869267c9db8ae708b6ab1ce")]
    [InlineData(Argon2Type.Argon2id, Argon2Version.Version13, 64, 2, 1, 128, 8, 16, 0, 0, "cb061f2f3957e8963123897eb982942a1e1855c8bd42ed28cfc93317c3feec00a9c8a9ecdfa8f319351a08f714db32a1e1cf6f37c5f1c5106efe143184c450ca4d4ba27ed5dcedc07f7f277c0a3de4e0bba9253d1f0bab027dd447b989fcbe1d87d205f9a7bddaca7534c6f32fa40a83854e8d19eea8906ded1bfe3e99fa912f")]
    [InlineData(Argon2Type.Argon2id, Argon2Version.Version13, 64, 2, 1, 32, 0, 16, 0, 0, "9ede2f56b4bf0ee3298d06e6264818f056f94f4891c8af5d3d4b48b846c040cd")]
    [InlineData(Argon2Type.Argon2id, Argon2Version.Version13, 64, 2, 1, 32, 8, 8, 0, 0, "ada9bc0cd12f5dec1c4664f4a3d2d56065635fb668a42341e3d73d925ae9f502")]
    [InlineData(Argon2Type.Argon2id, Argon2Version.Version13, 64, 2, 1, 32, 1000, 64, 0, 0, "15e0c9e500d3b11ab55f32b9fdcbb4666a308b200c8543fe56e66aba08f8b422")]
    [InlineData(Argon2Type.Argon2id, Argon2Version.Version13, 19456, 2, 1, 32, 28, 16, 0, 0, "8185cb536561402027c47f55285f7c9f9e8efe5ba0cfec14cfc871a5805cd10a")]
    [InlineData(Argon2Type.Argon2id, Argon2Version.Version13, 65536, 4, 4, 32, 28, 16, 0, 0, "0aa6dbecf0b9aa806435f03b2ac4e83276cd1aed42830afba7048b5957bc1cde")]
    public void Hash_MatchesVersion402(
        Argon2Type type, Argon2Version version, int memorySizeKB, int iterations, int parallelism, int hashLength,
        int passwordLength, int saltLength, int secretLength, int associatedDataLength, string expected)
    {
        var parameters = new Argon2Parameters
        {
            Type = type,
            Version = version,
            MemorySizeKB = memorySizeKB,
            Iterations = iterations,
            Parallelism = parallelism,
            HashLength = hashLength,
            Salt = Sequence(saltLength, 0x01),
            Secret = secretLength == 0 ? null : Sequence(secretLength, 0x03),
            AssociatedData = associatedDataLength == 0 ? null : Sequence(associatedDataLength, 0x04)
        };

        byte[] hash = new Argon2(parameters).Hash(Sequence(passwordLength, 0x70).AsSpan());

        Assert.Equal(expected, Convert.ToHexStringLower(hash));
    }

    private static byte[] Sequence(int length, int start) =>
        Enumerable.Range(start, length).Select(i => (byte)i).ToArray();
}
