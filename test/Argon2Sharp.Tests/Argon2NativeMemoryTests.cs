using Xunit;

namespace Argon2Sharp.Tests;

[CollectionDefinition(nameof(NativeMemoryCollection), DisableParallelization = true)]
public class NativeMemoryCollection;

[Collection(nameof(NativeMemoryCollection))]
public class Argon2NativeMemoryTests
{
    [Fact]
    public void Hash_OnManyThreads_ReleasesWorkingMemory()
    {
        if (!OperatingSystem.IsLinux())
            return;

        var parameters = Argon2Parameters.CreateDefault() with { Salt = Argon2.GenerateSalt() };
        new Argon2(parameters).Hash("password");
        long before = AnonymousRssKB();

        var threads = Enumerable.Range(0, 8)
            .Select(_ => new Thread(() =>
            {
                for (int i = 0; i < 5; i++)
                    new Argon2(parameters).Hash("password");
            }))
            .ToList();
        threads.ForEach(t => t.Start());
        threads.ForEach(t => t.Join());

        long growthMB = (AnonymousRssKB() - before) / 1024;
        // 4.0.1 kept a 19 MiB block per thread in the glibc heap: about 150 MiB here
        Assert.True(growthMB < 64, $"Anonymous RSS grew by {growthMB} MiB.");
    }

    private static long AnonymousRssKB()
    {
        string line = File.ReadLines("/proc/self/status").First(l => l.StartsWith("RssAnon:"));
        return long.Parse(line.Split(' ', StringSplitOptions.RemoveEmptyEntries)[1]);
    }
}
