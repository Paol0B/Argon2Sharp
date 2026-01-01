using System;
using System.Text;
using Xunit;

namespace Argon2Sharp.Tests
{
    public class Argon2ComplianceTests
    {
        [Fact]
        public void TestRfc9106_Argon2id_TestVector1()
        {
            // RFC 9106 Argon2id Test Vector
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

            byte[] expectedHash = new byte[]
            {
              0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
              0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59,
            };

            Assert.Equal(BitConverter.ToString(expectedHash), BitConverter.ToString(hash));
            Assert.True(argon2.Verify(password, hash));
        }

        [Fact]
        public void TestPhcFormat_Encoding_UsesDotInsteadOfPlus()
        {
            // Create a salt that will produce a '+' in standard Base64
            // 0xFB, 0xF0, 0x00 -> /fA= (no)
            // 0xFE -> /g==
            // 0xF8 -> +A== (in some positions)
            // Let's try to find a byte sequence that produces '+'
            // Base64 '+' is 62 (111110)
            // 001111 10xxxx
            // 3E ...

            // Easier: just check the implementation or use a known salt
            // But let's try to force it.
            // 0xFB (11111011) -> 111110 11xxxx -> +...

            byte[] salt = new byte[] { 0xFB };
            // Convert.ToBase64String(new byte[] { 0xFB }) -> "+w=="

            var parameters = new Argon2Parameters
            {
                Salt = salt,
                MemorySizeKB = 8,
                Iterations = 1,
                Parallelism = 1
            };

            byte[] hash = new byte[32]; // Dummy hash

            string phc = Argon2PhcFormat.Encode(hash, parameters);

            // Should contain '.' not '+'
            Assert.DoesNotContain("+", phc);
            // Should contain '.' (if it was +)
            // Actually, let's just check if it parses back correctly

            bool success = Argon2PhcFormat.TryDecode(phc, out byte[] decodedHash, out byte[] decodedSalt, out _, out _, out _, out _, out _);
            Assert.True(success, "Failed to decode PHC string");
            Assert.Equal(salt, decodedSalt);
        }

        [Fact]
        public void TestPhcFormat_Decoding_HandlesDot()
        {
            // Manually construct a PHC string with '.'
            // Salt: .n.n.n.n -> +n+n+n+n (Base64)
            // +n+n+n+n -> 0xFA, 0x7F, 0xA7, 0xFA, 0x7F, 0xA7
            string phc = "$argon2id$v=19$m=8,t=1,p=1$.n.n.n.n$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

            bool success = Argon2PhcFormat.TryDecode(phc, out byte[] decodedHash, out byte[] decodedSalt, out _, out _, out _, out _, out _);

            Assert.True(success, "Should decode PHC string with dots");

            byte[] expectedSalt = Convert.FromBase64String("+n+n+n+n");
            Assert.Equal(expectedSalt, decodedSalt);
        }
    }
}
