using System;

namespace CasDotnetSdk.Hashers
{
    public enum IHasherType
    {
        SHA = 0,
        Blake2 = 1
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
                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, "Unknown hasher type.");
            }
        }
    }
}
