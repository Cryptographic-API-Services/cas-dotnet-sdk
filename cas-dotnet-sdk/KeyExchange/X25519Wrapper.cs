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
    public class X25519Wrapper
    {
        private readonly OSPlatform _platform;
        private readonly BenchmarkSender _benchmarkSender;

        public X25519Wrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._benchmarkSender = new BenchmarkSender();
        }

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
                X25519LinuxWrapper.free_bytes(result.public_key);
                X25519LinuxWrapper.free_bytes(result.secret_key);
                X25519SecretPublicKey res = new X25519SecretPublicKey()
                {
                    PublicKey = publicKeyResult,
                    SecretKey = secretKeyResult
                };
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.KeyExchange, nameof(X25519Wrapper));
                return res;
            }
            else
            {
                X25519SecretPublicKeyResult result = X25519WindowsWrapper.generate_secret_and_public_key();
                byte[] secretKeyResult = new byte[result.secret_key_length];
                Marshal.Copy(result.secret_key, secretKeyResult, 0, secretKeyResult.Length);
                byte[] publicKeyResult = new byte[result.public_key_length];
                Marshal.Copy(result.public_key, publicKeyResult, 0, publicKeyResult.Length);
                X25519WindowsWrapper.free_bytes(result.public_key);
                X25519WindowsWrapper.free_bytes(result.secret_key);
                X25519SecretPublicKey res = new X25519SecretPublicKey()
                {
                    PublicKey = publicKeyResult,
                    SecretKey = secretKeyResult
                };
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.KeyExchange, nameof(X25519Wrapper));
                return res;
            }
        }

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
                X25519LinuxWrapper.free_bytes(result.shared_secret);
                X25519SharedSecret res = new X25519SharedSecret()
                {
                    SharedSecret = sharedSecret
                };
                DateTime end = DateTime.UtcNow;
                this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(X25519Wrapper));
                return res;
            }
            else
            {
                try
                {
                    X25519SharedSecretResult result = X25519WindowsWrapper.diffie_hellman(secretKey, secretKey.Length, otherUserPublicKey, otherUserPublicKey.Length);
                    byte[] sharedSecret = new byte[result.shared_secret_length];
                    Marshal.Copy(result.shared_secret, sharedSecret, 0, sharedSecret.Length);
                    X25519WindowsWrapper.free_bytes(result.shared_secret);
                    X25519SharedSecret res = new X25519SharedSecret()
                    {
                        SharedSecret = sharedSecret
                    };
                    DateTime end = DateTime.UtcNow;
                    this._benchmarkSender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Hash, nameof(X25519Wrapper));
                    return res;

                }
                catch (Exception ex)
                {
                    return new X25519SharedSecret() { };
                }
            }
        }
    }
}
