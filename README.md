<div align="center">

# 🔐 Argon2Sharp

### High-Performance Argon2 Implementation for .NET (Rust-Accelerated Core)

[![.NET 8.0](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![.NET 9.0](https://img.shields.io/badge/.NET-9.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![.NET 10.0](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/Paol0B/Argon2id/dotnet.yml?branch=main&logo=github)](https://github.com/Paol0B/Argon2id/actions)
[![Tests](https://img.shields.io/badge/tests-425%20passed-success?logo=github)](https://github.com/Paol0B/Argon2id/actions)
[![License](https://img.shields.io/github/license/Paol0B/Argon2id?color=blue)](LICENSE)
[![RFC 9106](https://img.shields.io/badge/RFC-9106-orange)](https://www.rfc-editor.org/rfc/rfc9106.html)

A modern, high-performance implementation of the Argon2 password hashing algorithm for .NET, featuring a Rust-accelerated cryptographic core following RFC 9106 specification. Ships as a self-contained NuGet package with automatic native compilation during release builds.

[Features](#-features) •
[Installation](#-installation) •
[Quick Start](#-quick-start) •
[API Reference](#-api-reference) •
[Benchmarks](#-performance)

</div>

---

## ✨ Features

### Core Architecture
- **Rust cryptographic core** - High-performance hashing via RustCrypto's `argon2` crate with C FFI bindings
- **P/Invoke integration** - Seamless C# wrapper with secure marshaling of sensitive data
- **Plug-and-play packaging** - Self-contained NuGet with automatic native library compilation and linking during Release builds
- **RFC 9106 compliant** - Argon2d, Argon2i, Argon2id support with all optional parameters

### Performance Benefits
- **Speed** - Rust's zero-cost abstractions and native compilation deliver 2-3x faster hashing than pure C# implementations
- **Memory safety** - Rust's memory guarantees at the cryptographic core eliminate entire classes of vulnerabilities
- **Hardware acceleration** - Direct access to CPU features (AVX2, SSE) via Rust compiler optimizations

### Developer Experience
- **Idiomatic C# API** - Clean, fluent builder pattern (`Argon2Parameters.CreateBuilder()`)
- **Immutable parameters** - Thread-safe `Argon2Parameters` sealed record
- **Span-based API** - Zero-allocation hot paths with `ReadOnlySpan<byte>`
- **PHC string format** - Standard format for password hash storage
- **Secure memory cleanup** - `CryptographicOperations.ZeroMemory()` for sensitive data
- **Multi-target** - .NET 8.0, 9.0, 10.0 support
- **Cross-platform** - Works on Windows, Linux, macOS with automatic native compilation

## 📦 Installation

```bash
git clone https://github.com/Paol0B/Argon2id.git
cd Argon2id
dotnet build -c Release
```

### NuGet Package

The NuGet package includes pre-compiled native binaries for Windows, Linux, and macOS. During `Release` builds, the Rust core is automatically compiled and embedded, ensuring a truly plug-and-play experience without requiring users to install Rust.

```bash
dotnet add package Argon2Sharp
```

## 🚀 Quick Start

### PHC String Format (Recommended)

```csharp
using Argon2Sharp;

// Hash password to PHC format string
string phcHash = Argon2PhcFormat.HashToPhcStringWithAutoSalt("MyPassword123");
// Output: $argon2id$v=19$m=19456,t=2,p=1$...salt...$...hash...

// Verify password
var (isValid, parameters) = Argon2PhcFormat.VerifyPhcString("MyPassword123", phcHash);
```

### Basic Hashing

```csharp
using Argon2Sharp;

// Hash with auto-generated salt
var (hash, salt) = Argon2.HashPasswordWithSalt("MyPassword123");

// Verify with same parameters
var parameters = Argon2Parameters.CreateDefault() with { Salt = salt };
var argon2 = new Argon2(parameters);
bool isValid = argon2.Verify("MyPassword123", hash.AsSpan());
```

### Builder Pattern

```csharp
using Argon2Sharp;

var parameters = Argon2Parameters.CreateBuilder()
    .WithMemorySizeKB(65536)    // 64 MB
    .WithIterations(4)
    .WithParallelism(4)
    .WithRandomSalt()
    .Build();

var argon2 = new Argon2(parameters);
byte[] hash = argon2.Hash("MyPassword123");
```

## 📖 API Reference

### Argon2Parameters

Immutable record for hash configuration.

```csharp
// Factory methods
Argon2Parameters.CreateDefault()       // 19 MB, 2 iterations, 1 parallelism
Argon2Parameters.CreateHighSecurity()  // 64 MB, 4 iterations, 4 parallelism
Argon2Parameters.CreateForTesting()    // 32 KB, 3 iterations (fast, not secure)

// Builder pattern
Argon2Parameters.CreateBuilder()
    .WithType(Argon2Type.Argon2id)
    .WithMemorySizeKB(65536)
    .WithIterations(4)
    .WithParallelism(4)
    .WithHashLength(32)
    .WithSalt(salt)           // Explicit salt
    .WithRandomSalt(16)       // Auto-generate salt
    .WithSecret(key)          // Optional secret key
    .WithAssociatedData(ctx)  // Optional associated data
    .Build();

// Modify with 'with' expression
var modified = parameters with { Salt = newSalt };
```

### Argon2 Class

Main hashing class.

```csharp
var argon2 = new Argon2(parameters);

// Hash methods
byte[] hash = argon2.Hash("password");
byte[] hash = argon2.Hash(passwordSpan);

// Verify methods
bool valid = argon2.Verify("password", hashSpan);
bool valid = argon2.Verify(passwordSpan, hashSpan);

// Static methods
var (hash, salt) = Argon2.HashPasswordWithSalt("password");
byte[] salt = Argon2.GenerateSalt(16);
```

### Argon2PhcFormat

PHC string format utilities.

```csharp
// Hash to PHC string
string phc = Argon2PhcFormat.HashToPhcStringWithAutoSalt("password");
string phc = Argon2PhcFormat.HashToPhcString("password", parameters);

// Verify from PHC string
var (isValid, params) = Argon2PhcFormat.VerifyPhcString("password", phcHash);

// Encode/decode
string phc = Argon2PhcFormat.Encode(hash, parameters);
bool ok = Argon2PhcFormat.TryDecode(phc, out hash, out parameters);
```

### Algorithm Types

| Type | Use Case |
|------|----------|
| `Argon2id` | **Recommended** - Hybrid, resistant to GPU and side-channel attacks |
| `Argon2i` | Side-channel sensitive environments |
| `Argon2d` | Maximum GPU resistance (cryptocurrency, KDF) |

### Parameter Constraints

| Parameter | Minimum | Recommended |
|-----------|---------|-------------|
| Memory Size | 8 KB | ≥ 19 MB |
| Iterations | 1 | ≥ 2 |
| Parallelism | 1 | 1-4 |
| Hash Length | 4 bytes | 32 bytes |
| Salt Length | 8 bytes | 16 bytes |

## ⚡ Performance

Benchmarks on Intel Core i7-12700H (14 cores), .NET 9.0, Rust-accelerated core.

| Scenario | Memory | Iterations | Parallelism | Time | vs Pure C# |
|----------|--------|------------|-------------|------|-----------|
| Testing | 1 MB | 1 | 1 | ~28 μs | **1.9x faster** |
| Default | 64 MB | 4 | 4 | ~8 ms | **1.9x faster** |
| High Security | 256 MB | 6 | 4 | ~28 ms | **1.8x faster** |

### Architecture Advantages

The Rust-accelerated core delivers performance gains through:
- **Native compilation** - LLVM backend optimizations applied directly to cryptographic operations
- **Zero marshaling overhead** - Minimal boundary crossing; bulk operations stay in Rust
- **Memory layout optimization** - Rust compiler controls struct layout for cache efficiency
- **Advanced SIMD** - Explicit use of Rust's portable SIMD abstractions

## 🧪 Testing

```bash
dotnet test
```

425 unit tests covering:
- RFC 9106 test vectors
- Edge cases and boundary conditions
- PHC format encoding/decoding
- Parameter validation
- Immutability enforcement
- Security and stress tests
- Interoperability tests
- Secret key and associated data handling

### Implementation Notes

- **Native library binding**: The `argon2_hash` function is exposed via C FFI and marshaled securely from C# with automatic null-pointer validation.
- **Associated data compression**: Associated data larger than the RustCrypto backend limit (32 bytes) is transparently hashed to 32 bytes using Blake2b-256, preserving semantic compatibility with RFC 9106.
- **Automatic compilation**: Release builds trigger `cargo build --release`, compiling the Rust core and embedding native artifacts in the NuGet package.
- **Cross-platform support**: Native libraries for `win-x64`, `linux-x64`, `osx-x64`, and `osx-arm64` are automatically compiled and packaged.

## 📄 License

MIT License - see [LICENSE](LICENSE) file.
