using System;

namespace CasDotnetSdk.KeyExchange.Types
{
    internal struct X25519SharedSecretResult
    {
        public IntPtr shared_secret;
        public long shared_secret_length;
        public int error_code;
    }
}
