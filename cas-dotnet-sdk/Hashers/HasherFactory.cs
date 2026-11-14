using System;

namespace CasDotnetSdk.Hashers
{
    public enum IHasherType
    {
        /// <summary>SHA-3 256 / 512 (<see cref="SHAWrapper"/>).</summary>
        SHA = 0,
        Blake2 = 1,
        /// <summary>SHA-2: SHA-256 / SHA-512 (<see cref="SHA2Wrapper"/>).</summary>
        SHA2 = 2
    }
    public static class HasherFactory
    {
        /// <summary>
        /// Gets a hasher based on the type provided.
        /// </summary>
        /// <param name="type"></param>
        /// <returns></returns>
        public static IHasherBase Get(IHasherType type)
        {
            switch (type)
            {
                case IHasherType.SHA:
                    return new SHAWrapper();
                case IHasherType.Blake2:
                    return new Blake2Wrapper();
                case IHasherType.SHA2:
                    return new SHA2Wrapper();
                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, "Unknown hasher type.");
            }
        }
    }
}
