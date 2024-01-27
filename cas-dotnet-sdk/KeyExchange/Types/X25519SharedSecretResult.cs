using System;

namespace CasDotnetSdk.KeyExchange.Types
{
    internal struct X25519SharedSecretResult
    {
        public IntPtr shared_secret;
        public int shared_secret_length;
    }
}
