using System;
using System.Runtime.InteropServices;
using CasDotnetSdk.Helpers;
using CasDotnetSdk.Symmetric.Linux;
using CasDotnetSdk.Symmetric.Types;
using CasDotnetSdk.Symmetric.Windows;
using CASHelpers;

namespace CasDotnetSdk.Symmetric
{
    public class AESWrapper : BaseWrapper
    {
        private readonly OSPlatform _platform;

        /// <summary>
        /// A wrapper class for AES-GCM 128 and 256 bit encryption and decryption.
        /// </summary>
        public AESWrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
        }

        /// <summary>
        /// Generates an AES 128 bit key.
        /// </summary>
        /// <returns></returns>
        public byte[] Aes128Key()
        {

            if (this._platform == OSPlatform.Linux)
            {
                AesKeyResult keyResult = AESLinuxWrapper.aes_128_key();
                byte[] key = new byte[keyResult.length];
                Marshal.Copy(keyResult.key, key, 0, keyResult.length);
                FreeMemoryHelper.FreeBytesMemory(keyResult.key);


                return key;
            }
            else
            {
                AesKeyResult keyResult = AESWindowsWrapper.aes_128_key();
                byte[] key = new byte[keyResult.length];
                Marshal.Copy(keyResult.key, key, 0, keyResult.length);
                FreeMemoryHelper.FreeBytesMemory(keyResult.key);


                return key;
            }
        }

        /// <summary>
        /// Generates an AES 128 bit key.
        /// </summary>
        /// <returns></returns>
        public byte[] Aes128KeyThreadpool()
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }


            if (this._platform == OSPlatform.Linux)
            {
                AesKeyResult keyResult = AESLinuxWrapper.aes_128_key_threadpool();
                byte[] key = new byte[keyResult.length];
                Marshal.Copy(keyResult.key, key, 0, keyResult.length);
                FreeMemoryHelper.FreeBytesMemory(keyResult.key);


                return key;
            }
            else
            {
                AesKeyResult keyResult = AESWindowsWrapper.aes_128_key_threadpool();
                byte[] key = new byte[keyResult.length];
                Marshal.Copy(keyResult.key, key, 0, keyResult.length);
                FreeMemoryHelper.FreeBytesMemory(keyResult.key);


                return key;
            }
        }

        /// <summary>
        /// Generates an AES 256 bit key.
        /// </summary>
        /// <returns></returns>
        public byte[] Aes256Key()
        {

            if (this._platform == OSPlatform.Linux)
            {
                AesKeyResult keyResult = AESLinuxWrapper.aes_256_key();
                byte[] key = new byte[keyResult.length];
                Marshal.Copy(keyResult.key, key, 0, keyResult.length);
                FreeMemoryHelper.FreeBytesMemory(keyResult.key);


                return key;
            }
            else
            {
                AesKeyResult keyPtr = AESWindowsWrapper.aes_256_key();
                byte[] key = new byte[keyPtr.length];
                Marshal.Copy(keyPtr.key, key, 0, keyPtr.length);
                FreeMemoryHelper.FreeBytesMemory(keyPtr.key);


                return key;
            }
        }

        /// <summary>
        /// Generates an AES 256 bit key.
        /// </summary>
        /// <returns></returns>
        public byte[] Aes256KeyThreadpool()
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }


            if (this._platform == OSPlatform.Linux)
            {
                AesKeyResult keyResult = AESLinuxWrapper.aes_256_key_threadpool();
                byte[] key = new byte[keyResult.length];
                Marshal.Copy(keyResult.key, key, 0, keyResult.length);
                FreeMemoryHelper.FreeBytesMemory(keyResult.key);


                return key;
            }
            else
            {
                AesKeyResult keyPtr = AESWindowsWrapper.aes_256_key_threadpool();
                byte[] key = new byte[keyPtr.length];
                Marshal.Copy(keyPtr.key, key, 0, keyPtr.length);
                FreeMemoryHelper.FreeBytesMemory(keyPtr.key);


                return key;
            }
        }

        /// <summary>
        /// Generates an AES 256 bit key and nonce based off a X25519 Diffie Hellman shared secret.
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>

        public Aes256KeyAndNonceX25519DiffieHellman Aes256KeyNonceX25519DiffieHellman(byte[] sharedSecret)
        {
            if (sharedSecret == null || sharedSecret.Length == 0)
            {
                throw new Exception("You must provide allocated data for X25519 shared secret to generate an AES Key");
            }


            if (this._platform == OSPlatform.Linux)
            {
                Aes256KeyAndNonceX25519DiffieHellmanStruct result = AESLinuxWrapper.aes_256_key_and_nonce_from_x25519_diffie_hellman_shared_secret(sharedSecret, sharedSecret.Length);
                byte[] aesKey = new byte[result.aes_key_ptr_length];
                Marshal.Copy(result.aes_key_ptr, aesKey, 0, result.aes_key_ptr_length);
                FreeMemoryHelper.FreeBytesMemory(result.aes_key_ptr);
                byte[] aesNonce = new byte[result.aes_nonce_ptr_length];
                Marshal.Copy(result.aes_nonce_ptr, aesNonce, 0, result.aes_nonce_ptr_length);
                FreeMemoryHelper.FreeBytesMemory(result.aes_nonce_ptr);
                Aes256KeyAndNonceX25519DiffieHellman keyAndNonce = new Aes256KeyAndNonceX25519DiffieHellman()
                {
                    AesKey = aesKey,
                    AesNonce = aesNonce
                };


                return keyAndNonce;
            }
            else
            {

                Aes256KeyAndNonceX25519DiffieHellmanStruct result = AESWindowsWrapper.aes_256_key_and_nonce_from_x25519_diffie_hellman_shared_secret(sharedSecret, sharedSecret.Length);
                byte[] aesKey = new byte[result.aes_key_ptr_length];
                Marshal.Copy(result.aes_key_ptr, aesKey, 0, result.aes_key_ptr_length);
                FreeMemoryHelper.FreeBytesMemory(result.aes_key_ptr);
                byte[] aesNonce = new byte[result.aes_nonce_ptr_length];
                Marshal.Copy(result.aes_nonce_ptr, aesNonce, 0, result.aes_nonce_ptr_length);
                FreeMemoryHelper.FreeBytesMemory(result.aes_nonce_ptr);
                Aes256KeyAndNonceX25519DiffieHellman keyAndNonce = new Aes256KeyAndNonceX25519DiffieHellman()
                {
                    AesKey = aesKey,
                    AesNonce = aesNonce
                };


                return keyAndNonce;
            }
        }

        /// <summary>
        /// Generates an AES 256 bit key and nonce based off a X25519 Diffie Hellman shared secret on the threadpool.
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>

        public Aes256KeyAndNonceX25519DiffieHellman Aes256KeyNonceX25519DiffieHellmanThreadpool(byte[] sharedSecret)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (sharedSecret == null || sharedSecret.Length == 0)
            {
                throw new Exception("You must provide allocated data for X25519 shared secret to generate an AES Key");
            }


            if (this._platform == OSPlatform.Linux)
            {
                Aes256KeyAndNonceX25519DiffieHellmanStruct result = AESLinuxWrapper.aes_256_key_and_nonce_from_x25519_diffie_hellman_shared_secret_threadpool(sharedSecret, sharedSecret.Length);
                byte[] aesKey = new byte[result.aes_key_ptr_length];
                Marshal.Copy(result.aes_key_ptr, aesKey, 0, result.aes_key_ptr_length);
                FreeMemoryHelper.FreeBytesMemory(result.aes_key_ptr);
                byte[] aesNonce = new byte[result.aes_nonce_ptr_length];
                Marshal.Copy(result.aes_nonce_ptr, aesNonce, 0, result.aes_nonce_ptr_length);
                FreeMemoryHelper.FreeBytesMemory(result.aes_nonce_ptr);
                Aes256KeyAndNonceX25519DiffieHellman keyAndNonce = new Aes256KeyAndNonceX25519DiffieHellman()
                {
                    AesKey = aesKey,
                    AesNonce = aesNonce
                };


                return keyAndNonce;
            }
            else
            {

                Aes256KeyAndNonceX25519DiffieHellmanStruct result = AESWindowsWrapper.aes_256_key_and_nonce_from_x25519_diffie_hellman_shared_secret_threadpool(sharedSecret, sharedSecret.Length);
                byte[] aesKey = new byte[result.aes_key_ptr_length];
                Marshal.Copy(result.aes_key_ptr, aesKey, 0, result.aes_key_ptr_length);
                FreeMemoryHelper.FreeBytesMemory(result.aes_key_ptr);
                byte[] aesNonce = new byte[result.aes_nonce_ptr_length];
                Marshal.Copy(result.aes_nonce_ptr, aesNonce, 0, result.aes_nonce_ptr_length);
                FreeMemoryHelper.FreeBytesMemory(result.aes_nonce_ptr);
                Aes256KeyAndNonceX25519DiffieHellman keyAndNonce = new Aes256KeyAndNonceX25519DiffieHellman()
                {
                    AesKey = aesKey,
                    AesNonce = aesNonce
                };


                return keyAndNonce;
            }
        }

        /// <summary>
        /// Generates an AES 128 bit key and nonce based off a X25519 Diffie Hellman shared secret.
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public Aes256KeyAndNonceX25519DiffieHellman Aes128KeyNonceX25519DiffieHellman(byte[] sharedSecret)
        {
            if (sharedSecret == null || sharedSecret.Length == 0)
            {
                throw new Exception("You must provide allocated data for X25519 shared secret to generate an AES Key");
            }


            if (this._platform == OSPlatform.Linux)
            {
                Aes256KeyAndNonceX25519DiffieHellmanStruct result = AESLinuxWrapper.aes_128_key_and_nonce_from_x25519_diffie_hellman_shared_secret(sharedSecret, sharedSecret.Length);
                byte[] aesKey = new byte[result.aes_key_ptr_length];
                Marshal.Copy(result.aes_key_ptr, aesKey, 0, result.aes_key_ptr_length);
                FreeMemoryHelper.FreeCStringMemory(result.aes_key_ptr);
                byte[] aesNonce = new byte[result.aes_nonce_ptr_length];
                Marshal.Copy(result.aes_nonce_ptr, aesNonce, 0, result.aes_nonce_ptr_length);
                FreeMemoryHelper.FreeBytesMemory(result.aes_nonce_ptr);
                Aes256KeyAndNonceX25519DiffieHellman keyAndNonce = new Aes256KeyAndNonceX25519DiffieHellman()
                {
                    AesKey = aesKey,
                    AesNonce = aesNonce
                };


                return keyAndNonce;
            }
            else
            {

                Aes256KeyAndNonceX25519DiffieHellmanStruct result = AESWindowsWrapper.aes_128_key_and_nonce_from_x25519_diffie_hellman_shared_secret(sharedSecret, sharedSecret.Length);
                byte[] aesKey = new byte[result.aes_key_ptr_length];
                Marshal.Copy(result.aes_key_ptr, aesKey, 0, result.aes_key_ptr_length);
                FreeMemoryHelper.FreeBytesMemory(result.aes_key_ptr);
                byte[] aesNonce = new byte[result.aes_nonce_ptr_length];
                Marshal.Copy(result.aes_nonce_ptr, aesNonce, 0, result.aes_nonce_ptr_length);
                FreeMemoryHelper.FreeBytesMemory(result.aes_nonce_ptr);
                Aes256KeyAndNonceX25519DiffieHellman keyAndNonce = new Aes256KeyAndNonceX25519DiffieHellman()
                {
                    AesKey = aesKey,
                    AesNonce = aesNonce
                };


                return keyAndNonce;
            }
        }

        /// <summary>
        /// Generates an AES 128 bit key and nonce based off a X25519 Diffie Hellman shared secret on the threadpool.
        /// </summary>
        /// <param name="sharedSecret"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public Aes256KeyAndNonceX25519DiffieHellman Aes128KeyNonceX25519DiffieHellmanThreadpool(byte[] sharedSecret)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (sharedSecret == null || sharedSecret.Length == 0)
            {
                throw new Exception("You must provide allocated data for X25519 shared secret to generate an AES Key");
            }


            if (this._platform == OSPlatform.Linux)
            {
                Aes256KeyAndNonceX25519DiffieHellmanStruct result = AESLinuxWrapper.aes_128_key_and_nonce_from_x25519_diffie_hellman_shared_secret_threadpool(sharedSecret, sharedSecret.Length);
                byte[] aesKey = new byte[result.aes_key_ptr_length];
                Marshal.Copy(result.aes_key_ptr, aesKey, 0, result.aes_key_ptr_length);
                FreeMemoryHelper.FreeBytesMemory(result.aes_key_ptr);
                byte[] aesNonce = new byte[result.aes_nonce_ptr_length];
                Marshal.Copy(result.aes_nonce_ptr, aesNonce, 0, result.aes_nonce_ptr_length);
                FreeMemoryHelper.FreeBytesMemory(result.aes_nonce_ptr);
                Aes256KeyAndNonceX25519DiffieHellman keyAndNonce = new Aes256KeyAndNonceX25519DiffieHellman()
                {
                    AesKey = aesKey,
                    AesNonce = aesNonce
                };


                return keyAndNonce;
            }
            else
            {

                Aes256KeyAndNonceX25519DiffieHellmanStruct result = AESWindowsWrapper.aes_128_key_and_nonce_from_x25519_diffie_hellman_shared_secret_threadpool(sharedSecret, sharedSecret.Length);
                byte[] aesKey = new byte[result.aes_key_ptr_length];
                Marshal.Copy(result.aes_key_ptr, aesKey, 0, result.aes_key_ptr_length);
                FreeMemoryHelper.FreeBytesMemory(result.aes_key_ptr);
                byte[] aesNonce = new byte[result.aes_nonce_ptr_length];
                Marshal.Copy(result.aes_nonce_ptr, aesNonce, 0, result.aes_nonce_ptr_length);
                FreeMemoryHelper.FreeBytesMemory(result.aes_nonce_ptr);
                Aes256KeyAndNonceX25519DiffieHellman keyAndNonce = new Aes256KeyAndNonceX25519DiffieHellman()
                {
                    AesKey = aesKey,
                    AesNonce = aesNonce
                };


                return keyAndNonce;
            }
        }

        /// <summary>
        /// Encrypts with AES-256-GCM.
        /// </summary>
        /// <param name="nonceKey"></param>
        /// <param name="key"></param>
        /// <param name="toEncrypt"></param>
        /// <param name="sendBenchmark"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Aes256Encrypt(byte[] nonceKey, byte[] key, byte[] toEncrypt, bool sendBenchmark = true)
        {
            if (nonceKey?.Length == 0)
            {
                throw new Exception("You must provide a nonce to encrypt with AES 256");
            }
            if (key?.Length == 0)
            {
                throw new Exception("You must provide a key  to encrypt with AES 256");
            }
            if (toEncrypt == null || toEncrypt.Length <= 0)
            {
                throw new Exception("You must provide allocated data to encrypt with AES 256");
            }


            if (this._platform == OSPlatform.Linux)
            {
                AesBytesEncrypt encryptResult = AESLinuxWrapper.aes_256_encrypt_bytes_with_key(nonceKey, nonceKey.Length, key, key.Length, toEncrypt, toEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(encryptResult.ciphertext);
                return result;
            }
            else
            {
                AesBytesEncrypt encryptResult = AESWindowsWrapper.aes_256_encrypt_bytes_with_key(nonceKey, nonceKey.Length, key, key.Length, toEncrypt, toEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(encryptResult.ciphertext);
                return result;
            }
        }

        /// <summary>
        /// Encrypts with AES-256-GCM on the threadpool.
        /// </summary>
        /// <param name="nonceKey"></param>
        /// <param name="key"></param>
        /// <param name="toEncrypt"></param>
        /// <param name="sendBenchmark"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Aes256EncryptThreadpool(byte[] nonceKey, byte[] key, byte[] toEncrypt)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (nonceKey?.Length == 0)
            {
                throw new Exception("You must provide a nonce to encrypt with AES 256");
            }
            if (key?.Length == 0)
            {
                throw new Exception("You must provide a key  to encrypt with AES 256");
            }
            if (toEncrypt == null || toEncrypt.Length <= 0)
            {
                throw new Exception("You must provide allocated data to encrypt with AES 256");
            }


            if (this._platform == OSPlatform.Linux)
            {
                AesBytesEncrypt encryptResult = AESLinuxWrapper.aes_256_encrypt_bytes_with_key_threadpool(nonceKey, nonceKey.Length, key, key.Length, toEncrypt, toEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(encryptResult.ciphertext);
                return result;
            }
            else
            {
                AesBytesEncrypt encryptResult = AESWindowsWrapper.aes_256_encrypt_bytes_with_key_threadpool(nonceKey, nonceKey.Length, key, key.Length, toEncrypt, toEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(encryptResult.ciphertext);
                return result;
            }
        }

        /// <summary>
        /// Decrypts with AES-256-GCM.
        /// </summary>
        /// <param name="nonceKey"></param>
        /// <param name="key"></param>
        /// <param name="toDecrypt"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Aes256Decrypt(byte[] nonceKey, byte[] key, byte[] toDecrypt)
        {
            if (nonceKey?.Length == 0)
            {
                throw new Exception("You must provide a nonce to decrypt with AES 256");
            }
            if (key?.Length == 0)
            {
                throw new Exception("You must provide a key  to decrypt with AES 256");
            }
            if (toDecrypt == null || toDecrypt.Length <= 0)
            {
                throw new Exception("You must provide allocated data to decrypt with AES 256");
            }


            if (this._platform == OSPlatform.Linux)
            {
                AesBytesDecrypt encryptResult = AESLinuxWrapper.aes_256_decrypt_bytes_with_key(nonceKey, nonceKey.Length, key, key.Length, toDecrypt, toDecrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.plaintext, result, 0, encryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(encryptResult.plaintext);


                return result;
            }
            else
            {
                AesBytesDecrypt encryptResult = AESWindowsWrapper.aes_256_decrypt_bytes_with_key(nonceKey, nonceKey.Length, key, key.Length, toDecrypt, toDecrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.plaintext, result, 0, encryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(encryptResult.plaintext);


                return result;
            }
        }

        /// <summary>
        /// Decrypts with AES-256-GCM on the threadpool.
        /// </summary>
        /// <param name="nonceKey"></param>
        /// <param name="key"></param>
        /// <param name="toDecrypt"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Aes256DecryptThreadpool(byte[] nonceKey, byte[] key, byte[] toDecrypt)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (nonceKey?.Length == 0)
            {
                throw new Exception("You must provide a nonce to decrypt with AES 256");
            }
            if (key?.Length == 0)
            {
                throw new Exception("You must provide a key  to decrypt with AES 256");
            }
            if (toDecrypt == null || toDecrypt.Length <= 0)
            {
                throw new Exception("You must provide allocated data to decrypt with AES 256");
            }


            if (this._platform == OSPlatform.Linux)
            {
                AesBytesDecrypt encryptResult = AESLinuxWrapper.aes_256_decrypt_bytes_with_key_threadpool(nonceKey, nonceKey.Length, key, key.Length, toDecrypt, toDecrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.plaintext, result, 0, encryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(encryptResult.plaintext);


                return result;
            }
            else
            {
                AesBytesDecrypt encryptResult = AESWindowsWrapper.aes_256_decrypt_bytes_with_key_threadpool(nonceKey, nonceKey.Length, key, key.Length, toDecrypt, toDecrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.plaintext, result, 0, encryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(encryptResult.plaintext);


                return result;
            }
        }

        /// <summary>
        /// Encrypts with AES-128-GCM.
        /// </summary>
        /// <param name="nonceKey"></param>
        /// <param name="key"></param>
        /// <param name="dataToEncrypt"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Aes128Encrypt(byte[] nonceKey, byte[] key, byte[] dataToEncrypt)
        {
            if (nonceKey?.Length == 0)
            {
                throw new Exception("You must provide a nonce key to encrypt with AES 128");
            }
            if (key?.Length == 0)
            {
                throw new Exception("You must provide a key to encrypt with AES 128");
            }
            if (dataToEncrypt == null || dataToEncrypt?.Length == 0)
            {
                throw new Exception("You must provide allocated data to encrypt with AES 128");
            }


            if (this._platform == OSPlatform.Linux)
            {
                AesBytesEncrypt encryptResult = AESLinuxWrapper.aes_128_encrypt_bytes_with_key(nonceKey, nonceKey.Length, key, key.Length, dataToEncrypt, dataToEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(encryptResult.ciphertext);


                return result;
            }
            else
            {
                AesBytesEncrypt encryptResult = AESWindowsWrapper.aes_128_encrypt_bytes_with_key(nonceKey, nonceKey.Length, key, key.Length, dataToEncrypt, dataToEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(encryptResult.ciphertext);


                return result;
            }
        }

        /// <summary>
        /// Encrypts with AES-128-GCM on the threadpool.
        /// </summary>
        /// <param name="nonceKey"></param>
        /// <param name="key"></param>
        /// <param name="dataToEncrypt"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Aes128EncryptThreadpool(byte[] nonceKey, byte[] key, byte[] dataToEncrypt)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (nonceKey?.Length == 0)
            {
                throw new Exception("You must provide a nonce key to encrypt with AES 128");
            }
            if (key?.Length == 0)
            {
                throw new Exception("You must provide a key to encrypt with AES 128");
            }
            if (dataToEncrypt == null || dataToEncrypt?.Length == 0)
            {
                throw new Exception("You must provide allocated data to encrypt with AES 128");
            }


            if (this._platform == OSPlatform.Linux)
            {
                AesBytesEncrypt encryptResult = AESLinuxWrapper.aes_128_encrypt_bytes_with_key_threadpool(nonceKey, nonceKey.Length, key, key.Length, dataToEncrypt, dataToEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(encryptResult.ciphertext);


                return result;
            }
            else
            {
                AesBytesEncrypt encryptResult = AESWindowsWrapper.aes_128_encrypt_bytes_with_key_threadpool(nonceKey, nonceKey.Length, key, key.Length, dataToEncrypt, dataToEncrypt.Length);
                byte[] result = new byte[encryptResult.length];
                Marshal.Copy(encryptResult.ciphertext, result, 0, encryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(encryptResult.ciphertext);


                return result;
            }
        }

        /// <summary>
        /// Decrypts with AES-128-GCM.
        /// </summary>
        /// <param name="nonceKey"></param>
        /// <param name="key"></param>
        /// <param name="dataToDecrypt"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Aes128Decrypt(byte[] nonceKey, byte[] key, byte[] dataToDecrypt)
        {
            if (nonceKey?.Length == 0)
            {
                throw new Exception("You must provide a nonce key to decrypt with AES 128");
            }
            if (key?.Length == 0)
            {
                throw new Exception("You must provide a key to decrypt with AES 128");
            }
            if (dataToDecrypt?.Length == 0)
            {
                throw new Exception("You must provide allocated data to decrypt with AES 128");
            }


            if (this._platform == OSPlatform.Linux)
            {
                AesBytesDecrypt decryptResult = AESLinuxWrapper.aes_128_decrypt_bytes_with_key(nonceKey, nonceKey.Length, key, key.Length, dataToDecrypt, dataToDecrypt.Length);
                byte[] result = new byte[decryptResult.length];
                Marshal.Copy(decryptResult.plaintext, result, 0, decryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(decryptResult.plaintext);


                return result;
            }
            else
            {
                AesBytesDecrypt decryptResult = AESWindowsWrapper.aes_128_decrypt_bytes_with_key(nonceKey, nonceKey.Length, key, key.Length, dataToDecrypt, dataToDecrypt.Length);
                byte[] result = new byte[decryptResult.length];
                Marshal.Copy(decryptResult.plaintext, result, 0, decryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(decryptResult.plaintext);


                return result;
            }
        }

        /// <summary>
        /// Decrypts with AES-128-GCM on the threadpool.
        /// </summary>
        /// <param name="nonceKey"></param>
        /// <param name="key"></param>
        /// <param name="dataToDecrypt"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] Aes128DecryptThreadpool(byte[] nonceKey, byte[] key, byte[] dataToDecrypt)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (nonceKey?.Length == 0)
            {
                throw new Exception("You must provide a nonce key to decrypt with AES 128");
            }
            if (key?.Length == 0)
            {
                throw new Exception("You must provide a key to decrypt with AES 128");
            }
            if (dataToDecrypt?.Length == 0)
            {
                throw new Exception("You must provide allocated data to decrypt with AES 128");
            }


            if (this._platform == OSPlatform.Linux)
            {
                AesBytesDecrypt decryptResult = AESLinuxWrapper.aes_128_decrypt_bytes_with_key_threadpool(nonceKey, nonceKey.Length, key, key.Length, dataToDecrypt, dataToDecrypt.Length);
                byte[] result = new byte[decryptResult.length];
                Marshal.Copy(decryptResult.plaintext, result, 0, decryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(decryptResult.plaintext);


                return result;
            }
            else
            {
                AesBytesDecrypt decryptResult = AESWindowsWrapper.aes_128_decrypt_bytes_with_key_threadpool(nonceKey, nonceKey.Length, key, key.Length, dataToDecrypt, dataToDecrypt.Length);
                byte[] result = new byte[decryptResult.length];
                Marshal.Copy(decryptResult.plaintext, result, 0, decryptResult.length);
                FreeMemoryHelper.FreeBytesMemory(decryptResult.plaintext);


                return result;
            }
        }

        /// <summary>
        /// Generates a AES Nonce usuable for AES-128-GCM and AES-256-GCM.
        /// </summary>
        /// <returns></returns>
        public byte[] GenerateAESNonce()
        {

            if (this._platform == OSPlatform.Linux)
            {
                AesNonceResult nonceResult = AESLinuxWrapper.aes_nonce();
                byte[] result = new byte[nonceResult.length];
                Marshal.Copy(nonceResult.nonce, result, 0, nonceResult.length);
                FreeMemoryHelper.FreeBytesMemory(nonceResult.nonce);


                return result;
            }
            else
            {
                AesNonceResult nonceResult = AESWindowsWrapper.aes_nonce();
                byte[] result = new byte[nonceResult.length];
                Marshal.Copy(nonceResult.nonce, result, 0, nonceResult.length);
                FreeMemoryHelper.FreeBytesMemory(nonceResult.nonce);


                return result;
            }
        }

        /// <summary>
        /// Generates a AES Nonce usuable for AES-128-GCM and AES-256-GCM on the threadpool.
        /// </summary>
        /// <returns></returns>
        public byte[] GenerateAESNonceThreadpool()
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }


            if (this._platform == OSPlatform.Linux)
            {
                AesNonceResult nonceResult = AESLinuxWrapper.aes_nonce_threadpool();
                byte[] result = new byte[nonceResult.length];
                Marshal.Copy(nonceResult.nonce, result, 0, nonceResult.length);
                FreeMemoryHelper.FreeBytesMemory(nonceResult.nonce);


                return result;
            }
            else
            {
                AesNonceResult nonceResult = AESWindowsWrapper.aes_nonce_threadpool();
                byte[] result = new byte[nonceResult.length];
                Marshal.Copy(nonceResult.nonce, result, 0, nonceResult.length);
                FreeMemoryHelper.FreeBytesMemory(nonceResult.nonce);


                return result;
            }
        }
    }
}