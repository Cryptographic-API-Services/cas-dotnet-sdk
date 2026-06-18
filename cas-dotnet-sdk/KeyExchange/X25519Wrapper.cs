using CasCoreLib;
using CasDotnetSdk.Helpers;
using CasDotnetSdk.KeyExchange.Types;
using System;

namespace CasDotnetSdk.KeyExchange
{
    public unsafe class X25519Wrapper 
    {
        /// <summary>
        /// A wrapper class for working with X25519 key exchange algorithm.
        /// </summary>
        public X25519Wrapper()
        {
        }

        /// <summary>
        /// Generates a secret key and a public key using the X25519 algorithm.
        /// </summary>
        public X25519SecretPublicKey GenerateSecretAndPublicKey()
        {
            x25519SecretPublicKeyResult result = NativeMethods.generate_secret_and_public_key();
            return new X25519SecretPublicKey()
            {
                SecretKey = NativeByteBuffer.CopyAndFree(result.secret_key, result.secret_key_length),
                PublicKey = NativeByteBuffer.CopyAndFree(result.public_key, result.public_key_length)
            };
        }

        /// <summary>
        /// Generates a shared secret using the X25519 algorithm Diffie Hellman.
        /// </summary>
        public X25519SharedSecret GenerateSharedSecret(byte[] secretKey, byte[] otherUserPublicKey)
        {
            if (secretKey == null || secretKey.Length == 0)
            {
                throw new Exception("You must provide an allocated data array");
            }
            if (otherUserPublicKey == null || otherUserPublicKey.Length == 0)
            {
                throw new Exception("You must provide an allocated data array");
            }

            fixed (byte* secretPtr = NativePin.Of(secretKey))
            fixed (byte* publicPtr = NativePin.Of(otherUserPublicKey))
            {
                x25519SharedSecretResult result = NativeMethods.diffie_hellman(secretPtr, (nuint)secretKey.Length, publicPtr, (nuint)otherUserPublicKey.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "X25519 Diffie-Hellman");
                return new X25519SharedSecret()
                {
                    SharedSecret = NativeByteBuffer.CopyAndFree(result.shared_secret, result.shared_secret_length)
                };
            }
        }
    }
}
