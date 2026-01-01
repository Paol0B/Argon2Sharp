using System.Text;

namespace Argon2Sharp;

/// <summary>
/// PHC string format encoder/decoder for Argon2.
/// Format: $argon2{type}$v={version}$m={memory},t={iterations},p={parallelism}$salt$hash
/// </summary>
/// <remarks>
/// <para>The PHC (Password Hashing Competition) string format is a standard format for storing
/// password hashes along with their parameters, making them self-describing and portable.</para>
/// </remarks>
/// <example>
/// <code>
/// // Hash a password to PHC format
/// string phcHash = Argon2PhcFormat.HashToPhcString("password", 
///     Argon2Parameters.CreateBuilder().WithRandomSalt().Build());
/// 
/// // Verify a password
/// var (isValid, parameters) = Argon2PhcFormat.VerifyPhcString("password", phcHash);
/// </code>
/// </example>
public static class Argon2PhcFormat
{
    /// <summary>
    /// Encodes hash, salt, and parameters into PHC format string.
    /// Example: $argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhlcmU
    /// </summary>
    /// <param name="hash">The hash bytes.</param>
    /// <param name="salt">The salt bytes.</param>
    /// <param name="type">The Argon2 type.</param>
    /// <param name="memorySizeKB">Memory size in KB.</param>
    /// <param name="iterations">Number of iterations.</param>
    /// <param name="parallelism">Degree of parallelism.</param>
    /// <param name="version">Argon2 version.</param>
    /// <returns>PHC format string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when hash or salt is null.</exception>
    /// <exception cref="ArgumentException">Thrown when type is invalid.</exception>
    public static string Encode(
        byte[] hash,
        byte[] salt,
        Argon2Type type,
        int memorySizeKB,
        int iterations,
        int parallelism,
        Argon2Version version = Argon2Version.Version13)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(salt);

        string typeStr = type switch
        {
            Argon2Type.Argon2d => "argon2d",
            Argon2Type.Argon2i => "argon2i",
            Argon2Type.Argon2id => "argon2id",
            _ => throw new ArgumentException("Invalid Argon2 type", nameof(type))
        };

        string versionStr = ((int)version).ToString();
        string saltB64 = Convert.ToBase64String(salt).TrimEnd('=').Replace('+', '.');
        string hashB64 = Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '.');

        return $"${typeStr}$v={versionStr}$m={memorySizeKB},t={iterations},p={parallelism}${saltB64}${hashB64}";
    }

    /// <summary>
    /// Encodes hash and parameters into PHC format string.
    /// </summary>
    /// <param name="hash">The hash bytes.</param>
    /// <param name="parameters">The Argon2 parameters (must include salt).</param>
    /// <returns>PHC format string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when hash or parameters is null.</exception>
    /// <exception cref="ArgumentException">Thrown when parameters.Salt is null.</exception>
    public static string Encode(byte[] hash, Argon2Parameters parameters)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(parameters);
        
        if (parameters.Salt == null)
            throw new ArgumentException("Parameters must include salt", nameof(parameters));

        return Encode(hash, parameters.Salt, parameters.Type, parameters.MemorySizeKB,
            parameters.Iterations, parameters.Parallelism, parameters.Version);
    }

    /// <summary>
    /// Decodes a PHC format string into its components.
    /// </summary>
    /// <param name="phcString">The PHC format string to decode.</param>
    /// <param name="hash">Decoded hash bytes.</param>
    /// <param name="salt">Decoded salt bytes.</param>
    /// <param name="type">Decoded Argon2 type.</param>
    /// <param name="memorySizeKB">Decoded memory size in KB.</param>
    /// <param name="iterations">Decoded iterations count.</param>
    /// <param name="parallelism">Decoded parallelism degree.</param>
    /// <param name="version">Decoded Argon2 version.</param>
    /// <returns>True if decoding succeeded, false otherwise.</returns>
    public static bool TryDecode(
        string phcString,
        out byte[]? hash,
        out byte[]? salt,
        out Argon2Type type,
        out int memorySizeKB,
        out int iterations,
        out int parallelism,
        out Argon2Version version)
    {
        hash = null;
        salt = null;
        type = Argon2Type.Argon2id;
        memorySizeKB = 0;
        iterations = 0;
        parallelism = 0;
        version = Argon2Version.Version13;

        if (string.IsNullOrEmpty(phcString))
            return false;

        string[] parts = phcString.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 5)
            return false;

        // Parse type
        type = parts[0] switch
        {
            "argon2d" => Argon2Type.Argon2d,
            "argon2i" => Argon2Type.Argon2i,
            "argon2id" => Argon2Type.Argon2id,
            _ => (Argon2Type)(-1) // Invalid type marker
        };

        // Return false for invalid type
        if ((int)type == -1)
            return false;

        // Parse version
        if (parts[1].StartsWith("v="))
        {
            if (!int.TryParse(parts[1][2..], out int v))
                return false;
            version = (Argon2Version)v;
        }
        else
        {
            return false;
        }

        // Parse parameters
        string[] parameters = parts[2].Split(',');
        if (parameters.Length != 3)
            return false;

        foreach (string param in parameters)
        {
            string[] kv = param.Split('=');
            if (kv.Length != 2)
                return false;

            switch (kv[0])
            {
                case "m":
                    if (!int.TryParse(kv[1], out memorySizeKB))
                        return false;
                    break;
                case "t":
                    if (!int.TryParse(kv[1], out iterations))
                        return false;
                    break;
                case "p":
                    if (!int.TryParse(kv[1], out parallelism))
                        return false;
                    break;
                default:
                    return false;
            }
        }

        // Parse salt
        try
        {
            string saltB64 = parts[3].Replace('.', '+');
            // Add padding if needed
            int padding = (4 - (saltB64.Length % 4)) % 4;
            saltB64 += new string('=', padding);
            salt = Convert.FromBase64String(saltB64);
        }
        catch
        {
            return false;
        }

        // Parse hash
        try
        {
            string hashB64 = parts[4].Replace('.', '+');
            // Add padding if needed
            int padding = (4 - (hashB64.Length % 4)) % 4;
            hashB64 += new string('=', padding);
            hash = Convert.FromBase64String(hashB64);
        }
        catch
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Decodes a PHC format string into Argon2Parameters and hash.
    /// </summary>
    /// <param name="phcString">The PHC format string to decode.</param>
    /// <param name="hash">Decoded hash bytes.</param>
    /// <param name="parameters">Decoded Argon2Parameters.</param>
    /// <returns>True if decoding succeeded, false otherwise.</returns>
    public static bool TryDecode(string phcString, out byte[]? hash, out Argon2Parameters? parameters)
    {
        hash = null;
        parameters = null;

        if (!TryDecode(phcString, out hash, out byte[]? salt, out Argon2Type type,
            out int memorySizeKB, out int iterations, out int parallelism, out Argon2Version version))
        {
            return false;
        }

        if (hash == null || salt == null)
            return false;

        parameters = new Argon2Parameters
        {
            Type = type,
            Version = version,
            MemorySizeKB = memorySizeKB,
            Iterations = iterations,
            Parallelism = parallelism,
            HashLength = hash.Length,
            Salt = salt
        };

        return true;
    }

    /// <summary>
    /// Hashes a password and returns PHC format string.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <param name="parameters">Argon2 parameters (must include salt).</param>
    /// <returns>PHC format string containing the hash and all parameters.</returns>
    /// <exception cref="ArgumentNullException">Thrown when password or parameters is null.</exception>
    /// <exception cref="ArgumentException">Thrown when parameters.Salt is null.</exception>
    public static string HashToPhcString(string password, Argon2Parameters parameters)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(parameters);
        
        if (parameters.Salt == null)
            throw new ArgumentException("Parameters must include salt", nameof(parameters));

        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        return Encode(hash, parameters);
    }

    /// <summary>
    /// Hashes a password with auto-generated salt and returns PHC format string.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <param name="parameters">Optional Argon2 parameters (salt will be auto-generated if not provided).</param>
    /// <param name="saltLength">Length of auto-generated salt (default 16 bytes).</param>
    /// <returns>PHC format string containing the hash and all parameters.</returns>
    /// <exception cref="ArgumentNullException">Thrown when password is null.</exception>
    public static string HashToPhcStringWithAutoSalt(string password, Argon2Parameters? parameters = null, int saltLength = 16)
    {
        ArgumentNullException.ThrowIfNull(password);
        
        var salt = Argon2.GenerateSalt(saltLength);
        var p = (parameters ?? Argon2Parameters.CreateDefault()) with { Salt = salt };

        return HashToPhcString(password, p);
    }

    /// <summary>
    /// Verifies a password against a PHC format hash string and returns the extracted parameters.
    /// </summary>
    /// <param name="password">Password to verify.</param>
    /// <param name="phcString">PHC format hash string.</param>
    /// <returns>A tuple containing: IsValid (true if password matches), Parameters (extracted parameters if valid, null otherwise).</returns>
    /// <exception cref="ArgumentNullException">Thrown when password or phcString is null.</exception>
    public static (bool IsValid, Argon2Parameters? Parameters) VerifyPhcString(string password, string phcString)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(phcString);

        if (!TryDecode(phcString, out byte[]? hash, out Argon2Parameters? parameters))
        {
            return (false, null);
        }

        if (hash == null || parameters == null)
            return (false, null);

        var argon2 = new Argon2(parameters);
        bool isValid = argon2.Verify(password, hash.AsSpan());

        return (isValid, isValid ? parameters : null);
    }

    /// <summary>
    /// Hashes a password and returns PHC format string with generated salt.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <param name="memorySizeKB">Memory size in KB.</param>
    /// <param name="iterations">Number of iterations.</param>
    /// <param name="parallelism">Degree of parallelism.</param>
    /// <param name="hashLength">Output hash length in bytes.</param>
    /// <param name="type">Argon2 type.</param>
    /// <returns>PHC format string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when password is null.</exception>
    [Obsolete("Use HashToPhcString(string, Argon2Parameters) or HashToPhcStringWithAutoSalt() instead. This method will be removed in v4.0.")]
    public static string HashPassword(
        string password,
        int memorySizeKB = 19456,
        int iterations = 2,
        int parallelism = 1,
        int hashLength = 32,
        Argon2Type type = Argon2Type.Argon2id)
    {
        ArgumentNullException.ThrowIfNull(password);

        byte[] salt = Argon2.GenerateSalt(16);
        
        var parameters = new Argon2Parameters
        {
            Type = type,
            MemorySizeKB = memorySizeKB,
            Iterations = iterations,
            Parallelism = parallelism,
            HashLength = hashLength,
            Salt = salt
        };

        var argon2 = new Argon2(parameters);
        byte[] hash = argon2.Hash(password);

        return Encode(hash, salt, type, memorySizeKB, iterations, parallelism);
    }

    /// <summary>
    /// Verifies a password against a PHC format hash string.
    /// </summary>
    /// <param name="password">Password to verify.</param>
    /// <param name="phcHash">PHC format hash string.</param>
    /// <returns>True if password matches, false otherwise.</returns>
    /// <exception cref="ArgumentNullException">Thrown when password or phcHash is null.</exception>
    [Obsolete("Use VerifyPhcString(string, string) which returns a tuple with parameters. This method will be removed in v4.0.")]
    public static bool VerifyPassword(string password, string phcHash)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(phcHash);

        var (isValid, _) = VerifyPhcString(password, phcHash);
        return isValid;
    }
}
