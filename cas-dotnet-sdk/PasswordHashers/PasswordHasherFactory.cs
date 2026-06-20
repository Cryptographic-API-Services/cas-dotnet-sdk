using System;

namespace CasDotnetSdk.PasswordHashers
{
    public enum PasswordHasherType
    {
        Argon2 = 1,
        BCrypt = 2,
        SCrypt = 3
    }

    public static class PasswordHasherFactory
    {
        public static IPasswordHasherBase Get(PasswordHasherType type)
        {
            return type switch
            {
                PasswordHasherType.Argon2 => new Argon2Wrapper(),
                PasswordHasherType.BCrypt => new BcryptWrapper(),
                PasswordHasherType.SCrypt => new SCryptWrapper(),
                _ => throw new ArgumentOutOfRangeException(nameof(type), type, "Unsupported password hasher type.")
            };
        }
    }
}
