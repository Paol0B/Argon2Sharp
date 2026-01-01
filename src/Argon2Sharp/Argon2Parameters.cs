using System.Security.Cryptography;

namespace Argon2Sharp;

/// <summary>
/// Immutable parameters for Argon2 hash computation.
/// All parameters are validated according to RFC 9106 specifications.
/// Use <see cref="CreateBuilder"/> to create a new instance with custom parameters.
/// </summary>
/// <remarks>
/// <para>This class is immutable and thread-safe. Use the <see cref="Builder"/> class for fluent parameter construction.</para>
/// <para>For most password hashing scenarios, use one of the factory methods:
/// <see cref="CreateDefault"/>, <see cref="CreateHighSecurity"/>, or <see cref="CreateForTesting"/>.</para>
/// </remarks>
/// <example>
/// <code>
/// // Using factory method
/// var parameters = Argon2Parameters.CreateDefault() with { Salt = mySalt };
///
/// // Using builder
/// var parameters = Argon2Parameters.CreateBuilder()
///     .WithMemorySizeKB(65536)
///     .WithIterations(4)
///     .WithParallelism(4)
///     .WithSalt(salt)
///     .Build();
/// </code>
/// </example>
public sealed record Argon2Parameters
{
    /// <summary>
    /// Argon2 algorithm type (Argon2d, Argon2i, or Argon2id).
    /// Default: Argon2id (recommended by RFC 9106).
    /// </summary>
    public Argon2Type Type { get; init; } = Argon2Type.Argon2id;

    /// <summary>
    /// Argon2 version.
    /// Default: Version13 (current RFC 9106 version).
    /// </summary>
    public Argon2Version Version { get; init; } = Argon2Version.Version13;

    /// <summary>
    /// Memory size in kilobytes.
    /// Minimum: 8 * Parallelism KB.
    /// Recommended: at least 19 MB (19456 KB) for password hashing.
    /// </summary>
    public int MemorySizeKB { get; init; } = 19456;

    /// <summary>
    /// Number of iterations (time cost).
    /// Minimum: 1.
    /// Recommended: at least 2 for password hashing.
    /// </summary>
    public int Iterations { get; init; } = 2;

    /// <summary>
    /// Degree of parallelism (number of threads).
    /// Minimum: 1.
    /// Maximum: 2^24 - 1.
    /// Recommended: match number of CPU cores, typically 1-4 for password hashing.
    /// </summary>
    public int Parallelism { get; init; } = 1;

    /// <summary>
    /// Desired hash output length in bytes.
    /// Minimum: 4 bytes.
    /// Typical: 32 bytes (256 bits) or 64 bytes (512 bits).
    /// </summary>
    public int HashLength { get; init; } = 32;

    /// <summary>
    /// Salt bytes (required).
    /// Minimum length: 8 bytes.
    /// Recommended: 16 bytes or more.
    /// Must be cryptographically random.
    /// </summary>
    public byte[]? Salt { get; init; }

    /// <summary>
    /// Optional secret/key for keyed hashing.
    /// Maximum length: 2^32 - 1 bytes.
    /// </summary>
    public byte[]? Secret { get; init; }

    /// <summary>
    /// Optional associated data (additional input).
    /// Maximum length: 2^32 - 1 bytes.
    /// </summary>
    public byte[]? AssociatedData { get; init; }

    /// <summary>
    /// Use the Rust-based native implementation for core operations.
    /// Requires the native library to be available.
    /// </summary>
    public bool UseRust { get; init; } = false;

    /// <summary>
    /// Reserved for future use: Maximum degree of parallelism for lane processing.
    /// Currently not used - sequential processing is always employed for correctness.
    /// </summary>
    /// <remarks>
    /// This property is reserved for potential future parallel processing optimization.
    /// Due to Argon2's data-dependent addressing creating cross-lane dependencies,
    /// parallel lane processing requires careful synchronization not yet implemented.
    /// </remarks>
    public int? MaxDegreeOfParallelism { get; init; }

    /// <summary>
    /// Creates default parameters suitable for password hashing.
    /// Uses Argon2id with RFC 9106 recommended minimum parameters.
    /// </summary>
    /// <returns>Default parameters with 19 MB memory, 2 iterations, 1 parallelism, 32-byte hash.</returns>
    public static Argon2Parameters CreateDefault()
    {
        return new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version13,
            MemorySizeKB = 19456,      // 19 MB
            Iterations = 2,             // 2 passes
            Parallelism = 1,            // Single-threaded
            HashLength = 32             // 256-bit output
        };
    }

    /// <summary>
    /// Creates high-security parameters for password hashing.
    /// Higher memory cost and iteration count.
    /// </summary>
    /// <returns>High-security parameters with 64 MB memory, 4 iterations, 4 parallelism, 32-byte hash.</returns>
    public static Argon2Parameters CreateHighSecurity()
    {
        return new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version13,
            MemorySizeKB = 65536,      // 64 MB
            Iterations = 4,             // 4 passes
            Parallelism = 4,            // 4 threads
            HashLength = 32             // 256-bit output
        };
    }

    /// <summary>
    /// Creates parameters suitable for testing (low resource usage).
    /// NOT recommended for production use.
    /// </summary>
    /// <returns>Test parameters with 32 KB memory, 3 iterations, 4 parallelism, 32-byte hash.</returns>
    public static Argon2Parameters CreateForTesting()
    {
        return new Argon2Parameters
        {
            Type = Argon2Type.Argon2id,
            Version = Argon2Version.Version13,
            MemorySizeKB = 32,         // 32 KB
            Iterations = 3,             // 3 passes
            Parallelism = 4,            // 4 threads
            HashLength = 32             // 256-bit output
        };
    }

    /// <summary>
    /// Creates a new <see cref="Builder"/> instance for fluent parameter construction.
    /// </summary>
    /// <returns>A new builder instance with default values.</returns>
    /// <example>
    /// <code>
    /// var parameters = Argon2Parameters.CreateBuilder()
    ///     .WithMemorySizeKB(65536)
    ///     .WithIterations(4)
    ///     .WithParallelism(4)
    ///     .WithSalt(salt)
    ///     .Build();
    /// </code>
    /// </example>
    public static Builder CreateBuilder() => new();

    /// <summary>
    /// Validates all parameters according to RFC 9106 requirements.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when parameters are invalid.</exception>
    public void Validate()
    {
        if (Salt == null || Salt.Length < 8)
            throw new ArgumentException("Salt must be at least 8 bytes");

        if (MemorySizeKB < 8)
            throw new ArgumentException("Memory size must be at least 8 KB");

        if (MemorySizeKB < 8 * Parallelism)
            throw new ArgumentException($"Memory size must be at least {8 * Parallelism} KB (8 * Parallelism)");

        if (Iterations < 1)
            throw new ArgumentException("Iterations must be at least 1");

        if (Parallelism < 1 || Parallelism > 0xFFFFFF)
            throw new ArgumentException("Parallelism must be between 1 and 16777215");

        if (HashLength < 4)
            throw new ArgumentException("Hash length must be at least 4 bytes");

        if (MaxDegreeOfParallelism.HasValue && MaxDegreeOfParallelism.Value < 1)
            throw new ArgumentException("MaxDegreeOfParallelism must be at least 1 if specified");
    }

    /// <summary>
    /// Creates a deep copy of the current parameters with cloned byte arrays.
    /// </summary>
    /// <returns>A new instance with cloned byte arrays.</returns>
    [Obsolete("Use 'with' expression for creating modified copies. Example: parameters with { Salt = newSalt }")]
    public Argon2Parameters DeepCopy()
    {
        return this with
        {
            Salt = Salt != null ? (byte[])Salt.Clone() : null,
            Secret = Secret != null ? (byte[])Secret.Clone() : null,
            AssociatedData = AssociatedData != null ? (byte[])AssociatedData.Clone() : null
        };
    }

    /// <summary>
    /// Fluent builder for creating <see cref="Argon2Parameters"/> instances.
    /// </summary>
    /// <remarks>
    /// Use <see cref="CreateBuilder"/> to create a new builder instance.
    /// All methods return the builder instance for method chaining.
    /// Call <see cref="Build"/> to create the final immutable parameters.
    /// </remarks>
    public sealed class Builder
    {
        private Argon2Type _type = Argon2Type.Argon2id;
        private Argon2Version _version = Argon2Version.Version13;
        private int _memorySizeKB = 19456;
        private int _iterations = 2;
        private int _parallelism = 1;
        private int _hashLength = 32;
        private byte[]? _salt;
        private byte[]? _secret;
        private byte[]? _associatedData;
        private int? _maxDegreeOfParallelism;
        private bool _useRust;

        /// <summary>
        /// Sets the Argon2 algorithm type.
        /// </summary>
        /// <param name="type">The Argon2 type (Argon2d, Argon2i, or Argon2id).</param>
        /// <returns>This builder instance for method chaining.</returns>
        public Builder WithType(Argon2Type type)
        {
            _type = type;
            return this;
        }

        /// <summary>
        /// Sets the Argon2 version.
        /// </summary>
        /// <param name="version">The Argon2 version.</param>
        /// <returns>This builder instance for method chaining.</returns>
        public Builder WithVersion(Argon2Version version)
        {
            _version = version;
            return this;
        }

        /// <summary>
        /// Sets the memory size in kilobytes.
        /// </summary>
        /// <param name="memorySizeKB">Memory size in KB (minimum: 8 KB).</param>
        /// <returns>This builder instance for method chaining.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when value is less than 8.</exception>
        public Builder WithMemorySizeKB(int memorySizeKB)
        {
            if (memorySizeKB < 8)
                throw new ArgumentOutOfRangeException(nameof(memorySizeKB), "Memory size must be at least 8 KB");
            _memorySizeKB = memorySizeKB;
            return this;
        }

        /// <summary>
        /// Sets the number of iterations (time cost).
        /// </summary>
        /// <param name="iterations">Number of iterations (minimum: 1).</param>
        /// <returns>This builder instance for method chaining.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when value is less than 1.</exception>
        public Builder WithIterations(int iterations)
        {
            if (iterations < 1)
                throw new ArgumentOutOfRangeException(nameof(iterations), "Iterations must be at least 1");
            _iterations = iterations;
            return this;
        }

        /// <summary>
        /// Sets the degree of parallelism.
        /// </summary>
        /// <param name="parallelism">Degree of parallelism (1 to 16777215).</param>
        /// <returns>This builder instance for method chaining.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when value is out of valid range.</exception>
        public Builder WithParallelism(int parallelism)
        {
            if (parallelism < 1 || parallelism > 0xFFFFFF)
                throw new ArgumentOutOfRangeException(nameof(parallelism), "Parallelism must be between 1 and 16777215");
            _parallelism = parallelism;
            return this;
        }

        /// <summary>
        /// Sets the desired hash output length.
        /// </summary>
        /// <param name="hashLength">Hash length in bytes (minimum: 4).</param>
        /// <returns>This builder instance for method chaining.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when value is less than 4.</exception>
        public Builder WithHashLength(int hashLength)
        {
            if (hashLength < 4)
                throw new ArgumentOutOfRangeException(nameof(hashLength), "Hash length must be at least 4 bytes");
            _hashLength = hashLength;
            return this;
        }

        /// <summary>
        /// Sets the salt bytes.
        /// </summary>
        /// <param name="salt">Salt bytes (minimum 8 bytes).</param>
        /// <returns>This builder instance for method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when salt is null.</exception>
        /// <exception cref="ArgumentException">Thrown when salt is less than 8 bytes.</exception>
        public Builder WithSalt(byte[] salt)
        {
            ArgumentNullException.ThrowIfNull(salt);
            if (salt.Length < 8)
                throw new ArgumentException("Salt must be at least 8 bytes", nameof(salt));
            _salt = (byte[])salt.Clone();
            return this;
        }

        /// <summary>
        /// Generates a cryptographically random salt.
        /// </summary>
        /// <param name="length">Salt length in bytes (minimum 8, default 16).</param>
        /// <returns>This builder instance for method chaining.</returns>
        /// <exception cref="ArgumentException">Thrown when length is less than 8.</exception>
        public Builder WithRandomSalt(int length = 16)
        {
            if (length < 8)
                throw new ArgumentException("Salt length must be at least 8 bytes", nameof(length));
            _salt = RandomNumberGenerator.GetBytes(length);
            return this;
        }

        /// <summary>
        /// Sets the optional secret/key for keyed hashing.
        /// </summary>
        /// <param name="secret">Secret bytes or null to disable.</param>
        /// <returns>This builder instance for method chaining.</returns>
        public Builder WithSecret(byte[]? secret)
        {
            _secret = secret != null ? (byte[])secret.Clone() : null;
            return this;
        }

        /// <summary>
        /// Sets the optional associated data.
        /// </summary>
        /// <param name="associatedData">Associated data bytes or null to disable.</param>
        /// <returns>This builder instance for method chaining.</returns>
        public Builder WithAssociatedData(byte[]? associatedData)
        {
            _associatedData = associatedData != null ? (byte[])associatedData.Clone() : null;
            return this;
        }

        /// <summary>
        /// Sets the maximum degree of parallelism for lane processing.
        /// </summary>
        /// <param name="maxDegreeOfParallelism">Maximum parallel tasks, or null for single-threaded.</param>
        /// <returns>This builder instance for method chaining.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when value is less than 1.</exception>
        public Builder WithMaxDegreeOfParallelism(int? maxDegreeOfParallelism)
        {
            if (maxDegreeOfParallelism.HasValue && maxDegreeOfParallelism.Value < 1)
                throw new ArgumentOutOfRangeException(nameof(maxDegreeOfParallelism), "MaxDegreeOfParallelism must be at least 1 if specified");
            _maxDegreeOfParallelism = maxDegreeOfParallelism;
            return this;
        }

        /// <summary>
        /// Sets whether to use the Rust-based native implementation.
        /// </summary>
        /// <param name="useRust">True to use Rust implementation, false for C#.</param>
        /// <returns>This builder instance for method chaining.</returns>
        public Builder WithRustImplementation(bool useRust = true)
        {
            _useRust = useRust;
            return this;
        }

        /// <summary>
        /// Builds and validates the <see cref="Argon2Parameters"/> instance.
        /// </summary>
        /// <returns>A new immutable <see cref="Argon2Parameters"/> instance.</returns>
        /// <exception cref="ArgumentException">Thrown when parameters are invalid.</exception>
        public Argon2Parameters Build()
        {
            var parameters = new Argon2Parameters
            {
                Type = _type,
                Version = _version,
                MemorySizeKB = _memorySizeKB,
                Iterations = _iterations,
                Parallelism = _parallelism,
                HashLength = _hashLength,
                Salt = _salt,
                Secret = _secret,
                AssociatedData = _associatedData,
                MaxDegreeOfParallelism = _maxDegreeOfParallelism,
                UseRust = _useRust
            };

            parameters.Validate();
            return parameters;
        }

        /// <summary>
        /// Builds the <see cref="Argon2Parameters"/> instance without salt validation.
        /// Useful when salt will be set later using 'with' expression.
        /// </summary>
        /// <returns>A new immutable <see cref="Argon2Parameters"/> instance (salt not validated).</returns>
        /// <exception cref="ArgumentException">Thrown when non-salt parameters are invalid.</exception>
        public Argon2Parameters BuildWithoutSaltValidation()
        {
            var parameters = new Argon2Parameters
            {
                Type = _type,
                Version = _version,
                MemorySizeKB = _memorySizeKB,
                Iterations = _iterations,
                Parallelism = _parallelism,
                HashLength = _hashLength,
                Salt = _salt,
                Secret = _secret,
                AssociatedData = _associatedData,
                MaxDegreeOfParallelism = _maxDegreeOfParallelism,
                UseRust = _useRust
            };

            // Validate everything except salt
            if (parameters.MemorySizeKB < 8)
                throw new ArgumentException("Memory size must be at least 8 KB");

            if (parameters.MemorySizeKB < 8 * parameters.Parallelism)
                throw new ArgumentException($"Memory size must be at least {8 * parameters.Parallelism} KB (8 * Parallelism)");

            if (parameters.Iterations < 1)
                throw new ArgumentException("Iterations must be at least 1");

            if (parameters.Parallelism < 1 || parameters.Parallelism > 0xFFFFFF)
                throw new ArgumentException("Parallelism must be between 1 and 16777215");

            if (parameters.HashLength < 4)
                throw new ArgumentException("Hash length must be at least 4 bytes");

            return parameters;
        }
    }
}
