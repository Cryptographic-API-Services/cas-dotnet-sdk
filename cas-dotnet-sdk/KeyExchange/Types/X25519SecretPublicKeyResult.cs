using System;

namespace CasDotnetSdk.KeyExchange.Types
{
    internal struct X25519SecretPublicKeyResult
    {
        public IntPtr secret_key;
        public long secret_key_length;
        public IntPtr public_key;
        public long public_key_length;
    }
}
