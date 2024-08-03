using CasDotnetSdk.Helpers;
using CasDotnetSdk.Http;
using CasDotnetSdk.KeyExchange.Linux;
using CasDotnetSdk.KeyExchange.Types;
using CasDotnetSdk.KeyExchange.Windows;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
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
        public X25519SecretPublicKey GenerateSecretAndPublicKey()
        {
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                X25519SecretPublicKeyResult result = X25519LinuxWrapper.generate_secret_and_public_key();
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
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.KeyExchange, nameof(X25519Wrapper));
                return res;
            }
            else
            {
                X25519SecretPublicKeyResult result = X25519WindowsWrapper.generate_secret_and_public_key();
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
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.KeyExchange, nameof(X25519Wrapper));
                return res;
            }
        }

        /// <summary>
        /// Generates a secret key and a public key using the X25519 algorithm on the threadpool.
        /// </summary>
        /// <returns></returns>
        public X25519SecretPublicKey GenerateSecretAndPublicKeyThreadpool()
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                X25519SecretPublicKeyResult result = X25519LinuxWrapper.generate_secret_and_public_key_threadpool();
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
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.KeyExchange, nameof(X25519Wrapper));
                return res;
            }
            else
            {
                X25519SecretPublicKeyResult result = X25519WindowsWrapper.generate_secret_and_public_key_threadpool();
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
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.KeyExchange, nameof(X25519Wrapper));
                return res;
            }
        }

        /// <summary>
        /// Generates a shared secret using the X25519 algorithm Diffie Hellman.
        /// </summary>
        /// <param name="secretKey"></param>
        /// <param name="otherUserPublicKey"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
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

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                X25519SharedSecretResult result = X25519LinuxWrapper.diffie_hellman(secretKey, secretKey.Length, otherUserPublicKey, otherUserPublicKey.Length);
                byte[] sharedSecret = new byte[result.shared_secret_length];
                Marshal.Copy(result.shared_secret, sharedSecret, 0, sharedSecret.Length);
                FreeMemoryHelper.FreeBytesMemory(result.shared_secret);
                X25519SharedSecret res = new X25519SharedSecret()
                {
                    SharedSecret = sharedSecret
                };
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(X25519Wrapper));
                return res;
            }
            else
            {
                X25519SharedSecretResult result = X25519WindowsWrapper.diffie_hellman(secretKey, secretKey.Length, otherUserPublicKey, otherUserPublicKey.Length);
                byte[] sharedSecret = new byte[result.shared_secret_length];
                Marshal.Copy(result.shared_secret, sharedSecret, 0, sharedSecret.Length);
                FreeMemoryHelper.FreeBytesMemory(result.shared_secret);
                X25519SharedSecret res = new X25519SharedSecret()
                {
                    SharedSecret = sharedSecret
                };
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(X25519Wrapper));
                return res;
            }
        }

        /// <summary>
        /// Generates a shared secret using the X25519 algorithm Diffie Hellman on the threadpool.
        /// </summary>
        /// <param name="secretKey"></param>
        /// <param name="otherUserPublicKey"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public X25519SharedSecret GenerateSharedSecretThreadpool(byte[] secretKey, byte[] otherUserPublicKey)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (secretKey == null || secretKey.Length == 0)
            {
                throw new Exception("You must provide an allocated data array");
            }
            if (otherUserPublicKey == null || otherUserPublicKey.Length == 0)
            {
                throw new Exception("You must provide an allocated data array");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                X25519SharedSecretResult result = X25519LinuxWrapper.diffie_hellman_threadpool(secretKey, secretKey.Length, otherUserPublicKey, otherUserPublicKey.Length);
                byte[] sharedSecret = new byte[result.shared_secret_length];
                Marshal.Copy(result.shared_secret, sharedSecret, 0, sharedSecret.Length);
                FreeMemoryHelper.FreeBytesMemory(result.shared_secret);
                X25519SharedSecret res = new X25519SharedSecret()
                {
                    SharedSecret = sharedSecret
                };
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(X25519Wrapper));
                return res;
            }
            else
            {
                X25519SharedSecretResult result = X25519WindowsWrapper.diffie_hellman_threadpool(secretKey, secretKey.Length, otherUserPublicKey, otherUserPublicKey.Length);
                byte[] sharedSecret = new byte[result.shared_secret_length];
                Marshal.Copy(result.shared_secret, sharedSecret, 0, sharedSecret.Length);
                FreeMemoryHelper.FreeBytesMemory(result.shared_secret);
                X25519SharedSecret res = new X25519SharedSecret()
                {
                    SharedSecret = sharedSecret
                };
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(X25519Wrapper));
                return res;
            }
        }
    }
}
