namespace Argon2Sharp.Core
{
    internal class Argon2Engine
    {
        private readonly Argon2Parameters _parameters;

        public Argon2Engine(Argon2Parameters parameters)
        {
            _parameters = parameters;
            if (_parameters.Salt == null)
                throw new ArgumentException("Salt is required for Argon2 hashing", nameof(parameters));
        }

        public unsafe void Hash(ReadOnlySpan<byte> password, Span<byte> output)
        {
            byte[] salt = _parameters.Salt!;

            uint typeId = _parameters.Type switch
            {
                Argon2Type.Argon2d => 0,
                Argon2Type.Argon2i => 1,
                Argon2Type.Argon2id => 2,
                _ => throw new ArgumentException("Invalid Argon2 type")
            };

            uint version = _parameters.Version switch
            {
                Argon2Version.Version10 => 0x10,
                Argon2Version.Version13 => 0x13,
                _ => throw new ArgumentException("Invalid Argon2 version")
            };

            fixed (byte* pPass = password)
            fixed (byte* pSalt = salt)
            fixed (byte* pSecret = _parameters.Secret)
            fixed (byte* pAd = _parameters.AssociatedData)
            fixed (byte* pOut = output)
            {
                int result = Argon2Native.Hash(
                    pPass, (nuint)password.Length,
                    pSalt, (nuint)salt.Length,
                    pSecret, (nuint)(_parameters.Secret?.Length ?? 0),
                    pAd, (nuint)(_parameters.AssociatedData?.Length ?? 0),
                    (uint)_parameters.Iterations,
                    (uint)_parameters.MemorySizeKB,
                    (uint)_parameters.Parallelism,
                    pOut,
                    (nuint)output.Length,
                    typeId,
                    version
                );

                if (result != 0)
                {
                    throw new InvalidOperationException($"Argon2 hashing failed with error code {result}");
                }
            }
        }
    }
}
