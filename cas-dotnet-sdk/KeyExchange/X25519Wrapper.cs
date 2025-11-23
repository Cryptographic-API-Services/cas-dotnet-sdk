using CasDotnetSdk.Fodies;
using CasDotnetSdk.Helpers;
using CasDotnetSdk.KeyExchange.Linux;
using CasDotnetSdk.KeyExchange.Types;
using CasDotnetSdk.KeyExchange.Windows;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.KeyExchange
{
    public class X25519Wrapper : BaseWrapper
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
        /// <returns></returns>
        /// 
        [BenchmarkSender]
        public X25519SecretPublicKey GenerateSecretAndPublicKey()
        {
            
            X25519SecretPublicKeyResult result = (this._platform == OSPlatform.Linux) ?
                X25519LinuxWrapper.generate_secret_and_public_key() :
                X25519WindowsWrapper.generate_secret_and_public_key();
            byte[] secretKeyResult = new byte[result.secret_key_length];
            Marshal.Copy(result.secret_key, secretKeyResult, 0, secretKeyResult.Length);
            byte[] publicKeyResult = new byte[result.public_key_length];
            Marshal.Copy(result.public_key, publicKeyResult, 0, publicKeyResult.Length);
            FreeMemoryHelper.FreeBytesMemory(result.public_key);
            FreeMemoryHelper.FreeBytesMemory(result.secret_key);
            X25519SecretPublicKey res = new X25519SecretPublicKey()
            {
                PublicKey = publicKeyResult,
                SecretKey = secretKeyResult
            };
            
            return res;
        }

        /// <summary>
        /// Generates a shared secret using the X25519 algorithm Diffie Hellman.
        /// </summary>
        /// <param name="secretKey"></param>
        /// <param name="otherUserPublicKey"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        /// 
        [BenchmarkSender]
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

            
            X25519SharedSecretResult result = (this._platform == OSPlatform.Linux) ?
                X25519LinuxWrapper.diffie_hellman(secretKey, secretKey.Length, otherUserPublicKey, otherUserPublicKey.Length)
                : X25519WindowsWrapper.diffie_hellman(secretKey, secretKey.Length, otherUserPublicKey, otherUserPublicKey.Length);
            byte[] sharedSecret = new byte[result.shared_secret_length];
            Marshal.Copy(result.shared_secret, sharedSecret, 0, sharedSecret.Length);
            FreeMemoryHelper.FreeBytesMemory(result.shared_secret);
            X25519SharedSecret res = new X25519SharedSecret()
            {
                SharedSecret = sharedSecret
            };
            

            return res;
        }
    }
}