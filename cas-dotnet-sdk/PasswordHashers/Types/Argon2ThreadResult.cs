using System;

namespace CasDotnetSdk.PasswordHashers.Types
{
    internal struct Argon2ThreadResult
    {
        public IntPtr passwords { get; set; }
        public int length { get; set; }
    }
}
