using CasDotnetSdk.Http;
using CasDotnetSdk.Sponges.Linux;
using CasDotnetSdk.Sponges.Types;
using CasDotnetSdk.Sponges.Windows;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Sponges
{
    public class AsconWrapper
    {
        private readonly OSPlatform _platform;
        private readonly BenchmarkSender _sender;
        public AsconWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
            this._sender = new BenchmarkSender();
        }

        public string Ascon128Key()
        {
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                IntPtr keyPtr = AsconLinuxWrapper.ascon_128_key();
                string key = Marshal.PtrToStringAnsi(keyPtr);
                AsconLinuxWrapper.free_cstring(keyPtr);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(AsconWrapper));
                return key;
            }
            else
            {
                IntPtr keyPtr = AsconWindowsWrapper.ascon_128_key();
                string key = Marshal.PtrToStringAnsi(keyPtr);
                AsconWindowsWrapper.free_cstring(keyPtr);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(AsconWrapper));
                return key;
            }
        }

        public string Ascon128Nonce()
        {
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                IntPtr noncePtr = AsconLinuxWrapper.ascon_128_nonce();
                string nonce = Marshal.PtrToStringAnsi(noncePtr);
                AsconLinuxWrapper.free_cstring(noncePtr);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(AsconWrapper));
                return nonce;
            }
            else
            {
                IntPtr noncePtr = AsconWindowsWrapper.ascon_128_nonce();
                string nonce = Marshal.PtrToStringAnsi(noncePtr);
                AsconWindowsWrapper.free_cstring(noncePtr);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(AsconWrapper));
                return nonce;
            }
        }

        public byte[] Ascon128Encrypt(string nonce, string key, byte[] toEncrypt)
        {
            if (string.IsNullOrEmpty(nonce))
            {
                throw new Exception("You must provide a nonce to encrypt with Ascon 128");
            }
            if (string.IsNullOrEmpty(key))
            {
                throw new Exception("You must provide a key to encrypt with Ascon 128");
            }
            if (toEncrypt == null || toEncrypt.Length == 0)
            {
                throw new Exception("You must provide data to encrypt with Ascon 128");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                Ascon128EncryptResultStruct encryptResult = AsconLinuxWrapper.ascon_128_encrypt(nonce, key, toEncrypt, toEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                AsconLinuxWrapper.free_bytes(encryptResult.ciphertext);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(AsconWrapper));
                return result;
            }
            else
            {
                Ascon128EncryptResultStruct encryptResult = AsconWindowsWrapper.ascon_128_encrypt(nonce, key, toEncrypt, toEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                AsconWindowsWrapper.free_bytes(encryptResult.ciphertext);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(AsconWrapper));
                return result;
            }
        }

        public byte[] Ascon128Decrypt(string nonce, string key, byte[] toDecrypt)
        {
            if (string.IsNullOrEmpty(nonce))
            {
                throw new Exception("You must provide a nonce to decrypt with Ascon 128");
            }
            if (string.IsNullOrEmpty(key))
            {
                throw new Exception("You must provide a key to decrypt with Ascon 128");
            }
            if (toDecrypt == null || toDecrypt.Length == 0)
            {
                throw new Exception("You must provide data to decrypt with Ascon 128");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                Ascon128DecryptResultStruct decryptResult = AsconLinuxWrapper.ascon_128_decrypt(nonce, key, toDecrypt, toDecrypt.Length);
                byte[] result = new byte[decryptResult.length];
                Marshal.Copy(decryptResult.plaintext, result, 0, decryptResult.length);
                AsconLinuxWrapper.free_bytes(decryptResult.plaintext);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(AsconWrapper));
                return result;
            }
            else
            {
                Ascon128DecryptResultStruct decryptResult = AsconWindowsWrapper.ascon_128_decrypt(nonce, key, toDecrypt, toDecrypt.Length);
                byte[] result = new byte[decryptResult.length];
                Marshal.Copy(decryptResult.plaintext, result, 0, decryptResult.length);
                AsconWindowsWrapper.free_bytes(decryptResult.plaintext);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Asymmetric, nameof(AsconWrapper));
                return result;
            }
        }
    }
}
