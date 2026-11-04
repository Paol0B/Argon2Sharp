using System.Text;
using Xunit;

namespace Argon2Sharp.Tests;

/// <summary>
/// Comprehensive error handling and exception tests.
/// Validates proper exception throwing and handling for invalid inputs and edge cases.
/// </summary>
public class Argon2ErrorHandlingTests
{
    #region Argon2 Constructor Error Tests

    [Fact]
    public void TestConstructor_NullParameters_ThrowsArgumentNullException()
    {
        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => new Argon2(null!));
        Assert.Equal("parameters", ex.ParamName);
    }

    [Fact]
    public void TestConstructor_NullSalt_ThrowsOnValidation()
    {
        // Arrange
        var parameters = new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = null
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => new Argon2(parameters).Hash("password"));
    }

    #endregion

    #region Hash Method Error Tests

    [Fact]
    public void TestHash_NullString_ThrowsArgumentNullException()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => argon2.Hash((string)null!));
        Assert.Equal("password", ex.ParamName);
    }

    [Fact]
    public void TestHash_OutputBufferWrongSize_ThrowsArgumentException()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);
        byte[] wrongSizeOutput = new byte[16]; // Expected 32

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => 
            argon2.Hash(Encoding.UTF8.GetBytes("password").AsSpan(), wrongSizeOutput));
        Assert.Contains("32 bytes", ex.Message);
    }

    [Fact]
    public void TestHash_OutputBufferTooLarge_ThrowsArgumentException()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);
        byte[] tooLargeOutput = new byte[64]; // Expected 32

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => 
            argon2.Hash(Encoding.UTF8.GetBytes("password").AsSpan(), tooLargeOutput));
    }

    [Fact]
    public void TestHash_OutputBufferTooSmall_ThrowsArgumentException()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);
        byte[] tooSmallOutput = new byte[8]; // Expected 32

        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            argon2.Hash(Encoding.UTF8.GetBytes("password").AsSpan(), tooSmallOutput));
    }

    #endregion

    #region Verify Method Error Tests

    [Fact]
    public void TestVerify_NullString_ThrowsArgumentNullException()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);
        byte[] hash = new byte[32];

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() => argon2.Verify((string)null!, hash.AsSpan()));
        Assert.Equal("password", ex.ParamName);
    }

    [Fact]
    public void TestVerify_WrongHashLength_ReturnsFalse()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);
        byte[] wrongLengthHash = new byte[16];

        // Act
        bool result = argon2.Verify("password", wrongLengthHash.AsSpan());

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void TestVerify_EmptyHash_ReturnsFalse()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);

        // Act
        bool result = argon2.Verify("password", Array.Empty<byte>().AsSpan());

        // Assert
        Assert.False(result);
    }

    #endregion

    #region Parameter Validation Error Tests

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(7)]
    public void TestParameters_InvalidMemorySizeKB_ThrowsArgumentOutOfRangeException(int memorySizeKB)
    {
        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Argon2Parameters.CreateBuilder().WithMemorySizeKB(memorySizeKB));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    public void TestParameters_InvalidIterations_ThrowsArgumentOutOfRangeException(int iterations)
    {
        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Argon2Parameters.CreateBuilder().WithIterations(iterations));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(16777216)] // > 2^24 - 1
    public void TestParameters_InvalidParallelism_ThrowsArgumentOutOfRangeException(int parallelism)
    {
        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Argon2Parameters.CreateBuilder().WithParallelism(parallelism));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void TestParameters_InvalidHashLength_ThrowsArgumentOutOfRangeException(int hashLength)
    {
        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Argon2Parameters.CreateBuilder().WithHashLength(hashLength));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    public void TestParameters_InvalidSaltLength_ThrowsArgumentException(int saltLength)
    {
        // Arrange
        byte[] salt = new byte[saltLength];

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            Argon2Parameters.CreateBuilder().WithSalt(salt));
    }

    [Fact]
    public void TestParameters_NullSalt_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            Argon2Parameters.CreateBuilder().WithSalt(null!));
    }

    [Fact]
    public void TestParameters_MemoryTooSmallForParallelism_ThrowsArgumentException()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() =>
            Argon2Parameters.CreateBuilder()
                .WithMemorySizeKB(32)
                .WithIterations(2)
                .WithParallelism(8) // Needs at least 64 KB (8 * 8)
                .WithHashLength(32)
                .WithSalt(salt)
                .Build());

        Assert.Contains("8 * Parallelism", ex.Message);
    }

    #endregion

    #region GenerateSalt Error Tests

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(7)]
    public void TestGenerateSalt_InvalidLength_ThrowsArgumentException(int length)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Argon2.GenerateSalt(length));
    }

    [Fact]
    public void TestRandomSalt_InvalidLength_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            Argon2Parameters.CreateBuilder().WithRandomSalt(7));
    }

    #endregion

    #region Static Method Error Tests

    [Fact]
    public void TestHashPasswordWithSalt_NullPassword_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Argon2.HashPasswordWithSalt(null!));
    }

    [Fact]
    public void TestToBase64_NullHash_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Argon2.ToBase64(null!));
    }

    [Fact]
    public void TestFromBase64_NullString_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Argon2.FromBase64(null!));
    }

    [Fact]
    public void TestFromBase64_InvalidBase64_ThrowsFormatException()
    {
        // Act & Assert
        Assert.Throws<FormatException>(() => Argon2.FromBase64("not-valid-base64!!!"));
    }

    #endregion

    #region PHC Format Error Tests

    [Fact]
    public void TestPhcEncode_NullHash_ThrowsArgumentNullException()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            Argon2PhcFormat.Encode(null!, salt, Argon2Type.Argon2id, 32, 2, 1));
    }

    [Fact]
    public void TestPhcEncode_NullSalt_ThrowsArgumentNullException()
    {
        // Arrange
        byte[] hash = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            Argon2PhcFormat.Encode(hash, null!, Argon2Type.Argon2id, 32, 2, 1));
    }

    [Fact]
    public void TestPhcEncode_NullParameters_ThrowsArgumentNullException()
    {
        // Arrange
        byte[] hash = new byte[32];

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            Argon2PhcFormat.Encode(hash, null!));
    }

    [Fact]
    public void TestPhcEncode_ParametersWithNullSalt_ThrowsArgumentException()
    {
        // Arrange
        byte[] hash = new byte[32];
        var parameters = Argon2Parameters.CreateDefault();

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            Argon2PhcFormat.Encode(hash, parameters));
    }

    [Fact]
    public void TestPhcHashPassword_NullPassword_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            Argon2PhcFormat.HashPassword(null!));
    }

    [Fact]
    public void TestPhcVerifyPassword_NullPassword_ThrowsArgumentNullException()
    {
        // Arrange
        string phcHash = "$argon2id$v=19$m=32,t=2,p=1$c29tZXNhbHQ$SGVsbG9Xb3JsZA";

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            Argon2PhcFormat.VerifyPassword(null!, phcHash));
    }

    [Fact]
    public void TestPhcVerifyPassword_NullPhcHash_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            Argon2PhcFormat.VerifyPassword("password", null!));
    }

    [Fact]
    public void TestPhcHashToPhcString_NullPassword_ThrowsArgumentNullException()
    {
        // Arrange
        var parameters = Argon2Parameters.CreateDefault() with { Salt = Argon2.GenerateSalt(16) };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            Argon2PhcFormat.HashToPhcString(null!, parameters));
    }

    [Fact]
    public void TestPhcHashToPhcString_NullParameters_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            Argon2PhcFormat.HashToPhcString("password", null!));
    }

    [Fact]
    public void TestPhcHashToPhcString_ParametersWithNullSalt_ThrowsArgumentException()
    {
        // Arrange
        var parameters = Argon2Parameters.CreateDefault();

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            Argon2PhcFormat.HashToPhcString("password", parameters));
    }

    [Fact]
    public void TestPhcHashToPhcStringWithAutoSalt_NullPassword_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            Argon2PhcFormat.HashToPhcStringWithAutoSalt(null!));
    }

    [Fact]
    public void TestPhcVerifyPhcString_NullPassword_ThrowsArgumentNullException()
    {
        // Arrange
        string phcHash = "$argon2id$v=19$m=32,t=2,p=1$c29tZXNhbHQ$SGVsbG9Xb3JsZA";

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            Argon2PhcFormat.VerifyPhcString(null!, phcHash));
    }

    [Fact]
    public void TestPhcVerifyPhcString_NullPhcString_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            Argon2PhcFormat.VerifyPhcString("password", null!));
    }

    #endregion

    #region PHC Format Decode Error Tests

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("$")]
    [InlineData("$$$$")]
    [InlineData("$argon2id$")]
    [InlineData("$argon2id$v=19$")]
    [InlineData("$argon2id$v=19$m=32,t=2,p=1$")]
    public void TestPhcDecode_InvalidFormats_ReturnsFalse(string? input)
    {
        // Act
        bool success = Argon2PhcFormat.TryDecode(
            input!,
            out byte[]? hash,
            out byte[]? salt,
            out Argon2Type type,
            out int m, out int t, out int p,
            out Argon2Version version);

        // Assert
        Assert.False(success);
    }

    [Fact]
    public void TestPhcDecode_InvalidType_ReturnsFalseOrThrows()
    {
        // Arrange
        string invalidType = "$argon2x$v=19$m=32,t=2,p=1$c29tZXNhbHQ$SGVsbG9Xb3JsZA";

        // Act
        bool success = false;
        try
        {
            success = Argon2PhcFormat.TryDecode(invalidType, out _, out _, out _, out _, out _, out _, out _);
        }
        catch (FormatException)
        {
            // Expected - invalid type throws
            success = false;
        }

        // Assert
        Assert.False(success);
    }

    [Fact]
    public void TestPhcDecode_InvalidBase64Salt_ReturnsFalse()
    {
        // Arrange
        string invalidSalt = "$argon2id$v=19$m=32,t=2,p=1$!!!invalid!!!$SGVsbG9Xb3JsZA";

        // Act
        bool success = Argon2PhcFormat.TryDecode(invalidSalt, out _, out _, out _, out _, out _, out _, out _);

        // Assert
        Assert.False(success);
    }

    [Fact]
    public void TestPhcDecode_InvalidBase64Hash_ReturnsFalse()
    {
        // Arrange
        string invalidHash = "$argon2id$v=19$m=32,t=2,p=1$c29tZXNhbHQ$!!!invalid!!!";

        // Act
        bool success = Argon2PhcFormat.TryDecode(invalidHash, out _, out _, out _, out _, out _, out _, out _);

        // Assert
        Assert.False(success);
    }

    [Fact]
    public void TestPhcDecode_InvalidMemoryParameter_ReturnsFalse()
    {
        // Arrange
        string invalidMemory = "$argon2id$v=19$m=abc,t=2,p=1$c29tZXNhbHQ$SGVsbG9Xb3JsZA";

        // Act
        bool success = Argon2PhcFormat.TryDecode(invalidMemory, out _, out _, out _, out _, out _, out _, out _);

        // Assert
        Assert.False(success);
    }

    [Fact]
    public void TestPhcDecode_InvalidIterationsParameter_ReturnsFalse()
    {
        // Arrange
        string invalidIterations = "$argon2id$v=19$m=32,t=abc,p=1$c29tZXNhbHQ$SGVsbG9Xb3JsZA";

        // Act
        bool success = Argon2PhcFormat.TryDecode(invalidIterations, out _, out _, out _, out _, out _, out _, out _);

        // Assert
        Assert.False(success);
    }

    [Fact]
    public void TestPhcDecode_InvalidParallelismParameter_ReturnsFalse()
    {
        // Arrange
        string invalidParallelism = "$argon2id$v=19$m=32,t=2,p=abc$c29tZXNhbHQ$SGVsbG9Xb3JsZA";

        // Act
        bool success = Argon2PhcFormat.TryDecode(invalidParallelism, out _, out _, out _, out _, out _, out _, out _);

        // Assert
        Assert.False(success);
    }

    [Fact]
    public void TestPhcDecode_InvalidVersionFormat_ReturnsFalse()
    {
        // Arrange
        string invalidVersion = "$argon2id$v=abc$m=32,t=2,p=1$c29tZXNhbHQ$SGVsbG9Xb3JsZA";

        // Act
        bool success = Argon2PhcFormat.TryDecode(invalidVersion, out _, out _, out _, out _, out _, out _, out _);

        // Assert
        Assert.False(success);
    }

    [Theory]
    [InlineData("$argon2id$v=20$m=32,t=2,p=1$c29tZXNhbHQ$SGVsbG9Xb3JsZA")]
    [InlineData("$argon2id$v=19$m=4,t=2,p=1$c29tZXNhbHQ$SGVsbG9Xb3JsZA")]
    [InlineData("$argon2id$v=19$m=32,t=0,p=1$c29tZXNhbHQ$SGVsbG9Xb3JsZA")]
    [InlineData("$argon2id$v=19$m=32,t=2,p=0$c29tZXNhbHQ$SGVsbG9Xb3JsZA")]
    [InlineData("$argon2id$v=19$m=32,t=2,p=1$c2FsdA$SGVsbG9Xb3JsZA")]
    [InlineData("$argon2id$v=19$m=32,t=2,p=1$c29tZXNhbHQ$SGVs")]
    public void TestVerifyPhcString_UnusableParameters_ReturnsFalse(string phcString)
    {
        var (isValid, parameters) = Argon2PhcFormat.VerifyPhcString("password", phcString);

        Assert.False(isValid);
        Assert.Null(parameters);
        Assert.False(Argon2PhcFormat.TryDecode(phcString, out _, out Argon2Parameters? _));
    }

    [Fact]
    public void TestHash_ShortSalt_ThrowsWithNativeReason()
    {
        var parameters = new Argon2Parameters { MemorySizeKB = 32, Iterations = 1, Salt = new byte[4] };

        var ex = Assert.Throws<InvalidOperationException>(() => new Argon2(parameters).Hash("password"));

        Assert.Contains("error code 7: invalid password, salt or hash length", ex.Message);
    }

    #endregion

    #region Builder Pattern Error Tests

    [Fact]
    public void TestBuilder_Build_WithoutSalt_ThrowsArgumentException()
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            Argon2Parameters.CreateBuilder()
                .WithMemorySizeKB(32)
                .WithIterations(2)
                .WithParallelism(1)
                .WithHashLength(32)
                .Build());
    }

    [Fact]
    public void TestBuilder_BuildWithoutSaltValidation_SucceedsWithoutSalt()
    {
        // Act
        var parameters = Argon2Parameters.CreateBuilder()
            .WithMemorySizeKB(32)
            .WithIterations(2)
            .WithParallelism(1)
            .WithHashLength(32)
            .BuildWithoutSaltValidation();

        // Assert
        Assert.Null(parameters.Salt);
        Assert.Equal(32, parameters.MemorySizeKB);
    }

    [Fact]
    public void TestBuilder_InvalidMaxDegreeOfParallelism_ThrowsArgumentOutOfRangeException()
    {
        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Argon2Parameters.CreateBuilder()
                .WithMaxDegreeOfParallelism(0));
    }

    [Fact]
    public void TestBuilder_NegativeMaxDegreeOfParallelism_ThrowsArgumentOutOfRangeException()
    {
        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Argon2Parameters.CreateBuilder()
                .WithMaxDegreeOfParallelism(-1));
    }

    #endregion

    #region Parameters Validation Error Tests

    [Fact]
    public void TestParameters_Validate_SaltTooShort_ThrowsArgumentException()
    {
        // Arrange
        var parameters = new Argon2Parameters
        {
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = new byte[7]
        };

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => parameters.Validate());
        Assert.Contains("Salt must be at least 8 bytes", ex.Message);
    }

    [Fact]
    public void TestParameters_Validate_MemoryTooSmall_ThrowsArgumentException()
    {
        // Arrange
        var parameters = new Argon2Parameters
        {
            MemorySizeKB = 7,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = new byte[16]
        };

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => parameters.Validate());
        Assert.Contains("Memory size must be at least 8 KB", ex.Message);
    }

    [Fact]
    public void TestParameters_Validate_IterationsTooLow_ThrowsArgumentException()
    {
        // Arrange
        var parameters = new Argon2Parameters
        {
            MemorySizeKB = 32,
            Iterations = 0,
            Parallelism = 1,
            HashLength = 32,
            Salt = new byte[16]
        };

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => parameters.Validate());
        Assert.Contains("Iterations must be at least 1", ex.Message);
    }

    [Fact]
    public void TestParameters_Validate_ParallelismTooLow_ThrowsArgumentException()
    {
        // Arrange
        var parameters = new Argon2Parameters
        {
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 0,
            HashLength = 32,
            Salt = new byte[16]
        };

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => parameters.Validate());
        Assert.Contains("Parallelism must be between", ex.Message);
    }

    [Fact]
    public void TestParameters_Validate_HashLengthTooShort_ThrowsArgumentException()
    {
        // Arrange
        var parameters = new Argon2Parameters
        {
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 3,
            Salt = new byte[16]
        };

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => parameters.Validate());
        Assert.Contains("Hash length must be at least 4 bytes", ex.Message);
    }

    [Fact]
    public void TestParameters_Validate_InvalidMaxDegreeOfParallelism_ThrowsArgumentException()
    {
        // Arrange
        var parameters = new Argon2Parameters
        {
            MemorySizeKB = 32,
            Iterations = 2,
            Parallelism = 1,
            HashLength = 32,
            Salt = new byte[16],
            MaxDegreeOfParallelism = 0
        };

        // Act & Assert
        var ex = Assert.Throws<ArgumentException>(() => parameters.Validate());
        Assert.Contains("MaxDegreeOfParallelism must be at least 1", ex.Message);
    }

    #endregion

    #region Edge Case Error Recovery Tests

    [Fact]
    public void TestErrorRecovery_AfterException_CanHashAgain()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);

        // Act - cause an exception
        Assert.Throws<ArgumentNullException>(() => argon2.Hash((string)null!));

        // Then try valid operation
        byte[] hash = argon2.Hash("validpassword");

        // Assert
        Assert.NotNull(hash);
        Assert.Equal(32, hash.Length);
    }

    [Fact]
    public void TestErrorRecovery_AfterVerifyFailure_CanVerifyAgain()
    {
        // Arrange
        byte[] salt = Argon2.GenerateSalt(16);
        var parameters = Argon2Parameters.CreateForTesting() with { Salt = salt };
        var argon2 = new Argon2(parameters);
        byte[] correctHash = argon2.Hash("password");

        // Act - verify with wrong hash length
        bool result1 = argon2.Verify("password", new byte[16].AsSpan());

        // Then try valid verification
        bool result2 = argon2.Verify("password", correctHash.AsSpan());

        // Assert
        Assert.False(result1);
        Assert.True(result2);
    }

    #endregion
}
