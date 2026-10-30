using System.Diagnostics;
using Xunit;

namespace Argon2Sharp.Tests;

/// <summary>
/// Regression tests for native memory retained after hashing (issue #14).
/// </summary>
[Collection(nameof(NativeMemoryCollection))]
[Trait("Category", "Memory")]
public class Argon2NativeMemoryTests
{
    [Fact]
    public async Task TestHashOnManyThreads_ReleasesWorkingMemory()
    {
        // Arrange
        var parameters = Argon2Parameters.CreateDefault() with { Salt = Argon2.GenerateSalt(16) };
        new Argon2(parameters with { MemorySizeKB = 64 }).Hash("warm-up");
        long before = MeasureMemory();

        // Act
        await HashOnThreadsAsync(parameters, threadCount: 8, hashesPerThread: 4);
        long growth = MeasureMemory() - before;

        // Assert - glibc used to keep at least one 19 MiB block per thread
        Assert.True(growth < 64L * 1024 * 1024, $"Memory grew by {growth / (1024 * 1024)} MiB");
    }

    private static Task HashOnThreadsAsync(Argon2Parameters parameters, int threadCount, int hashesPerThread)
    {
        var tasks = Enumerable.Range(0, threadCount)
            .Select(_ => Task.Factory.StartNew(() =>
            {
                var argon2 = new Argon2(parameters);
                for (int i = 0; i < hashesPerThread; i++)
                {
                    argon2.Hash("password");
                }
            }, TaskCreationOptions.LongRunning));

        return Task.WhenAll(tasks);
    }

    private static long MeasureMemory()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        if (OperatingSystem.IsLinux())
        {
            string line = File.ReadLines("/proc/self/status").First(l => l.StartsWith("RssAnon:", StringComparison.Ordinal));
            return long.Parse(line.Split(' ', StringSplitOptions.RemoveEmptyEntries)[1]) * 1024;
        }

        using var process = Process.GetCurrentProcess();
        return process.WorkingSet64;
    }
}

[CollectionDefinition(nameof(NativeMemoryCollection), DisableParallelization = true)]
public class NativeMemoryCollection
{
}
