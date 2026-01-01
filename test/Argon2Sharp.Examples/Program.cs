using Argon2Sharp;
using System.Text;

Console.WriteLine("=== Argon2Sharp v3.0 - Pure C# Argon2 Implementation ===");
Console.WriteLine("Based on RFC 9106 Specification\n");

// Example 1: Basic password hashing with tuple return (v3.0 API)
Console.WriteLine("Example 1: Basic Password Hashing");
Console.WriteLine("----------------------------------");
string password = "MySecurePassword123!";
var (hash, salt) = Argon2.HashPasswordWithSalt(password);
Console.WriteLine($"Password: {password}");
Console.WriteLine($"Salt (Base64): {Convert.ToBase64String(salt)}");
Console.WriteLine($"Hash (Base64): {Convert.ToBase64String(hash)}");
Console.WriteLine($"Hash Length: {hash.Length} bytes\n");

// Example 2: Password verification with Span API (v3.0)
Console.WriteLine("Example 2: Password Verification");
Console.WriteLine("----------------------------------");
var parameters = Argon2Parameters.CreateDefault() with { Salt = salt };
var argon2 = new Argon2(parameters);

bool isValid = argon2.Verify(password, hash.AsSpan());
Console.WriteLine($"Verification with correct password: {isValid}");

bool isInvalid = argon2.Verify("WrongPassword", hash.AsSpan());
Console.WriteLine($"Verification with wrong password: {isInvalid}\n");

// Example 3: Using PHC string format (v3.0 API)
Console.WriteLine("Example 3: PHC String Format");
Console.WriteLine("----------------------------------");
var parameters1 = Argon2Parameters.CreateBuilder()
    .WithMemorySizeKB(65536)
    .WithRustImplementation(true)
    .WithIterations(4)
    .WithParallelism(4)
    .WithRandomSalt()
    .Build();

string phcHash = Argon2PhcFormat.HashToPhcStringWithAutoSalt("SecurePassword", parameters1);
Console.WriteLine($"PHC Format Hash: {phcHash}");

var (phcValid, extractedParams) = Argon2PhcFormat.VerifyPhcString("SecurePassword", phcHash);
Console.WriteLine($"PHC Verification: {phcValid}");
if (extractedParams != null)
{
    Console.WriteLine($"Extracted Memory: {extractedParams.MemorySizeKB} KB");
    Console.WriteLine($"Extracted Iterations: {extractedParams.Iterations}\n");
}

// Example 4: Builder pattern (v3.0 API)
Console.WriteLine("Example 4: Builder Pattern");
Console.WriteLine("----------------------------------");
var builderParams = Argon2Parameters.CreateBuilder()
    .WithMemorySizeKB(65536)    // 64 MB
    .WithIterations(4)
    .WithParallelism(4)
    .WithRandomSalt()
    .Build();

var startTime = DateTime.Now;
var builderArgon2 = new Argon2(builderParams);
byte[] secureHash = builderArgon2.Hash("VeryImportantPassword");
var elapsedTime = (DateTime.Now - startTime).TotalMilliseconds;

Console.WriteLine($"Memory: {builderParams.MemorySizeKB} KB");
Console.WriteLine($"Iterations: {builderParams.Iterations}");
Console.WriteLine($"Parallelism: {builderParams.Parallelism}");
Console.WriteLine($"Hash computed in: {elapsedTime:F2} ms");
Console.WriteLine($"Hash (Base64): {Convert.ToBase64String(secureHash)}\n");

// Example 5: Different Argon2 types with immutable records
Console.WriteLine("Example 5: Different Argon2 Types");
Console.WriteLine("----------------------------------");
byte[] testSalt = Argon2.GenerateSalt(16);
string testPassword = "TestPassword";

foreach (Argon2Type type in Enum.GetValues<Argon2Type>())
{
    var typeParams = new Argon2Parameters
    {
        Type = type,
        MemorySizeKB = 32,
        Iterations = 3,
        Parallelism = 4,
        HashLength = 32,
        Salt = testSalt
    };

    var typeArgon2 = new Argon2(typeParams);
    byte[] typeHash = typeArgon2.Hash(testPassword);
    Console.WriteLine($"{type}: {Convert.ToBase64String(typeHash)}");
}
Console.WriteLine();

// Example 6: Using secret key and associated data
Console.WriteLine("Example 6: Secret Key and Associated Data");
Console.WriteLine("----------------------------------");
var advancedParams = Argon2Parameters.CreateBuilder()
    .WithType(Argon2Type.Argon2id)
    .WithMemorySizeKB(32)
    .WithIterations(3)
    .WithParallelism(4)
    .WithRandomSalt()
    .WithSecret(Encoding.UTF8.GetBytes("my-application-secret-key"))
    .WithAssociatedData(Encoding.UTF8.GetBytes("user-context-data"))
    .Build();

var advancedArgon2 = new Argon2(advancedParams);
byte[] advancedHash = advancedArgon2.Hash("password");
Console.WriteLine($"Hash with secret and associated data:");
Console.WriteLine($"{Convert.ToBase64String(advancedHash)}\n");

// Example 7: Performance comparison
Console.WriteLine("Example 7: Performance Comparison");
Console.WriteLine("----------------------------------");
var testParams = new[]
{
    ("Low Memory (32 KB)", Argon2Parameters.CreateBuilder().WithMemorySizeKB(32).WithIterations(3).WithParallelism(4).WithRandomSalt().Build()),
    ("Medium Memory (1 MB)", Argon2Parameters.CreateBuilder().WithMemorySizeKB(1024).WithIterations(3).WithParallelism(4).WithRandomSalt().Build()),
    ("High Memory (16 MB)", Argon2Parameters.CreateBuilder().WithMemorySizeKB(16384).WithIterations(3).WithParallelism(4).WithRandomSalt().Build())
};

string perfPassword = "BenchmarkPassword";
foreach (var (name, param) in testParams)
{
    var perfArgon2 = new Argon2(param);
    var perfStart = DateTime.Now;
    byte[] perfHash = perfArgon2.Hash(perfPassword);
    var perfElapsed = (DateTime.Now - perfStart).TotalMilliseconds;
    Console.WriteLine($"{name}: {perfElapsed:F2} ms");
}

// Example 8: Modify parameters with 'with' expression
Console.WriteLine("\nExample 8: Modify Parameters with 'with' Expression");
Console.WriteLine("----------------------------------");
var baseParams = Argon2Parameters.CreateDefault();
Console.WriteLine($"Base Memory: {baseParams.MemorySizeKB} KB");

var modifiedParams = baseParams with { MemorySizeKB = 65536, Salt = Argon2.GenerateSalt(16) };
Console.WriteLine($"Modified Memory: {modifiedParams.MemorySizeKB} KB");
Console.WriteLine($"Base unchanged: {baseParams.MemorySizeKB} KB (immutable!)");

Console.WriteLine("\n=== Examples completed successfully! ===");
