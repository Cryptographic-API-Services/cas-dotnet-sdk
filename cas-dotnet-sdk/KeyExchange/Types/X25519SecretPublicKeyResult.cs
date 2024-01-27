using System;

namespace CasDotnetSdk.KeyExchange.Types
{
    internal struct X25519SecretPublicKeyResult
    {
        public IntPtr secret_key;
        public int secret_key_length;
        public IntPtr public_key;
        public int public_key_length;
    }
}
