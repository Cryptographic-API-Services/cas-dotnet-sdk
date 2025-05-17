using System;
using System.Runtime.InteropServices;
using CasDotnetSdk.DigitalSignature.Linux;
using CasDotnetSdk.DigitalSignature.Types;
using CasDotnetSdk.DigitalSignature.Windows;
using CasDotnetSdk.Helpers;
using CASHelpers;

namespace CasDotnetSdk.DigitalSignature
{
    public class SHA256DigitalSignatureWrapper : BaseWrapper, IDigitalSignature
    {
        /// <summary>
        /// A wrapper class for the SHA256 Digital Signature (ED25519-Dalek and RSA).
        /// </summary>
        public SHA256DigitalSignatureWrapper()
        {
        }

        /// <summary>
        /// Creates a SHA256 ED25519 Digital Signature.
        /// </summary>
        /// <param name="dataToSign"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public SHAED25519DalekDigitialSignatureResult CreateED25519(byte[] dataToSign)
        {
            if (dataToSign == null || dataToSign.Length == 0)
            {
                throw new Exception("You must provide an allocated array of data to sign to create a SHA256 Ed25519 Digital Signature");
            }


            if (this._platform == OSPlatform.Linux)
            {
                SHAED25519DalekStructDigitalSignatureResult structResult = DigitalSignatureLinuxWrapper.sha256_ed25519_digital_signature(dataToSign, dataToSign.Length);
                byte[] publicKey = new byte[structResult.public_key_length];
                byte[] signature = new byte[structResult.signature_length];
                Marshal.Copy(structResult.public_key, publicKey, 0, publicKey.Length);
                Marshal.Copy(structResult.signature_raw_ptr, signature, 0, signature.Length);
                FreeMemoryHelper.FreeBytesMemory(structResult.public_key);
                FreeMemoryHelper.FreeBytesMemory(structResult.signature_raw_ptr);
                SHAED25519DalekDigitialSignatureResult result = new SHAED25519DalekDigitialSignatureResult()
                {
                    PublicKey = publicKey,
                    Signature = signature
                };


                return result;
            }
            else
            {
                SHAED25519DalekStructDigitalSignatureResult structResult = DigitalSignatureWindowsWrapper.sha256_ed25519_digital_signature(dataToSign, dataToSign.Length);
                byte[] publicKey = new byte[structResult.public_key_length];
                byte[] signature = new byte[structResult.signature_length];
                Marshal.Copy(structResult.public_key, publicKey, 0, publicKey.Length);
                Marshal.Copy(structResult.signature_raw_ptr, signature, 0, signature.Length);
                FreeMemoryHelper.FreeBytesMemory(structResult.public_key);
                FreeMemoryHelper.FreeBytesMemory(structResult.signature_raw_ptr);
                SHAED25519DalekDigitialSignatureResult result = new SHAED25519DalekDigitialSignatureResult()
                {
                    PublicKey = publicKey,
                    Signature = signature
                };


                return result;
            }
        }

        /// <summary>
        /// Creates a SHA256 ED25519 Digital Signature on the threadpool.
        /// </summary>
        /// <param name="dataToSign"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public SHAED25519DalekDigitialSignatureResult CreateED25519Threadpool(byte[] dataToSign)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (dataToSign == null || dataToSign.Length == 0)
            {
                throw new Exception("You must provide an allocated array of data to sign to create a SHA256 Ed25519 Digital Signature");
            }


            if (this._platform == OSPlatform.Linux)
            {
                SHAED25519DalekStructDigitalSignatureResult structResult = DigitalSignatureLinuxWrapper.sha256_ed25519_digital_signature_threadpool(dataToSign, dataToSign.Length);
                byte[] publicKey = new byte[structResult.public_key_length];
                byte[] signature = new byte[structResult.signature_length];
                Marshal.Copy(structResult.public_key, publicKey, 0, publicKey.Length);
                Marshal.Copy(structResult.signature_raw_ptr, signature, 0, signature.Length);
                FreeMemoryHelper.FreeBytesMemory(structResult.public_key);
                FreeMemoryHelper.FreeBytesMemory(structResult.signature_raw_ptr);
                SHAED25519DalekDigitialSignatureResult result = new SHAED25519DalekDigitialSignatureResult()
                {
                    PublicKey = publicKey,
                    Signature = signature
                };


                return result;
            }
            else
            {
                SHAED25519DalekStructDigitalSignatureResult structResult = DigitalSignatureWindowsWrapper.sha256_ed25519_digital_signature_threadpool(dataToSign, dataToSign.Length);
                byte[] publicKey = new byte[structResult.public_key_length];
                byte[] signature = new byte[structResult.signature_length];
                Marshal.Copy(structResult.public_key, publicKey, 0, publicKey.Length);
                Marshal.Copy(structResult.signature_raw_ptr, signature, 0, signature.Length);
                FreeMemoryHelper.FreeBytesMemory(structResult.public_key);
                FreeMemoryHelper.FreeBytesMemory(structResult.signature_raw_ptr);
                SHAED25519DalekDigitialSignatureResult result = new SHAED25519DalekDigitialSignatureResult()
                {
                    PublicKey = publicKey,
                    Signature = signature
                };


                return result;
            }
        }

        /// <summary>
        /// Creates a SHA256 RSA Digital Signature.
        /// </summary>
        /// <param name="rsaKeySize"></param>
        /// <param name="dataToSign"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public SHARSADigitalSignatureResult CreateRsa(int rsaKeySize, byte[] dataToSign)
        {
            if (rsaKeySize != 1024 && rsaKeySize != 2048 && rsaKeySize != 4096)
            {
                throw new Exception("Not a valid RSA key size");
            }
            if (dataToSign == null || dataToSign.Length == 0)
            {
                throw new Exception("Must provide an allocated data set to sign");
            }

            if (this._platform == OSPlatform.Linux)
            {

                SHARSAStructDigitialSignatureResult result = DigitalSignatureLinuxWrapper.sha_256_rsa_digital_signature(rsaKeySize, dataToSign, dataToSign.Length);
                byte[] signature = new byte[result.length];
                Marshal.Copy(result.signature, signature, 0, signature.Length);
                string publicKey = Marshal.PtrToStringAnsi(result.public_key);
                string privateKey = Marshal.PtrToStringAnsi(result.private_key);
                SHARSADigitalSignatureResult resultToReturn = new SHARSADigitalSignatureResult()
                {
                    Signature = signature,
                    PrivateKey = privateKey,
                    PublicKey = publicKey
                };
                FreeMemoryHelper.FreeBytesMemory(result.signature);
                FreeMemoryHelper.FreeCStringMemory(result.public_key);
                FreeMemoryHelper.FreeCStringMemory(result.private_key);

                return resultToReturn;
            }
            else
            {

                SHARSAStructDigitialSignatureResult result = DigitalSignatureWindowsWrapper.sha_256_rsa_digital_signature(rsaKeySize, dataToSign, dataToSign.Length);
                byte[] signature = new byte[result.length];
                Marshal.Copy(result.signature, signature, 0, signature.Length);
                string publicKey = Marshal.PtrToStringAnsi(result.public_key);
                string privateKey = Marshal.PtrToStringAnsi(result.private_key);
                SHARSADigitalSignatureResult resultToReturn = new SHARSADigitalSignatureResult()
                {
                    Signature = signature,
                    PrivateKey = privateKey,
                    PublicKey = publicKey
                };
                FreeMemoryHelper.FreeBytesMemory(result.signature);
                FreeMemoryHelper.FreeCStringMemory(result.public_key);
                FreeMemoryHelper.FreeCStringMemory(result.private_key);
                return resultToReturn;
            }
        }

        /// <summary>
        /// Creates a SHA256 RSA Digital Signature on the threadpool.
        /// </summary>
        /// <param name="rsaKeySize"></param>
        /// <param name="dataToSign"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public SHARSADigitalSignatureResult CreateRsaThreadpool(int rsaKeySize, byte[] dataToSign)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (rsaKeySize != 1024 && rsaKeySize != 2048 && rsaKeySize != 4096)
            {
                throw new Exception("Not a valid RSA key size");
            }
            if (dataToSign == null || dataToSign.Length == 0)
            {
                throw new Exception("Must provide an allocated data set to sign");
            }

            if (this._platform == OSPlatform.Linux)
            {

                SHARSAStructDigitialSignatureResult result = DigitalSignatureLinuxWrapper.sha_256_rsa_digital_signature_threadpool(rsaKeySize, dataToSign, dataToSign.Length);
                byte[] signature = new byte[result.length];
                Marshal.Copy(result.signature, signature, 0, signature.Length);
                string publicKey = Marshal.PtrToStringAnsi(result.public_key);
                string privateKey = Marshal.PtrToStringAnsi(result.private_key);
                SHARSADigitalSignatureResult resultToReturn = new SHARSADigitalSignatureResult()
                {
                    Signature = signature,
                    PrivateKey = privateKey,
                    PublicKey = publicKey
                };
                FreeMemoryHelper.FreeBytesMemory(result.signature);
                FreeMemoryHelper.FreeCStringMemory(result.public_key);
                FreeMemoryHelper.FreeCStringMemory(result.private_key);

                return resultToReturn;
            }
            else
            {

                SHARSAStructDigitialSignatureResult result = DigitalSignatureWindowsWrapper.sha_256_rsa_digital_signature_threadpool(rsaKeySize, dataToSign, dataToSign.Length);
                byte[] signature = new byte[result.length];
                Marshal.Copy(result.signature, signature, 0, signature.Length);
                string publicKey = Marshal.PtrToStringAnsi(result.public_key);
                string privateKey = Marshal.PtrToStringAnsi(result.private_key);
                SHARSADigitalSignatureResult resultToReturn = new SHARSADigitalSignatureResult()
                {
                    Signature = signature,
                    PrivateKey = privateKey,
                    PublicKey = publicKey
                };
                FreeMemoryHelper.FreeBytesMemory(result.signature);
                FreeMemoryHelper.FreeCStringMemory(result.public_key);
                FreeMemoryHelper.FreeCStringMemory(result.private_key);

                return resultToReturn;
            }
        }

        /// <summary>
        /// Verifies a SHA256 ED25519 Digital Signature.
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="dataToVerify"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public bool VerifyED25519(byte[] publicKey, byte[] dataToVerify, byte[] signature)
        {
            if (publicKey == null || publicKey.Length == 0)
            {
                throw new Exception("You must provide an allocated public key");
            }
            if (dataToVerify == null || dataToVerify.Length == 0)
            {
                throw new Exception("You must provide an allocated data to verify");
            }
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide an allocated signature ");
            }


            if (this._platform == OSPlatform.Linux)
            {
                bool result = DigitalSignatureLinuxWrapper.sha256_ed25519_digital_signature_verify(publicKey, publicKey.Length, dataToVerify, dataToVerify.Length, signature, signature.Length);


                return result;
            }
            else
            {
                bool result = DigitalSignatureWindowsWrapper.sha256_ed25519_digital_signature_verify(publicKey, publicKey.Length, dataToVerify, dataToVerify.Length, signature, signature.Length);


                return result;
            }
        }

        /// <summary>
        /// Verifies a SHA256 ED25519 Digital Signature on the threadpool.
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="dataToVerify"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public bool VerifyED25519Threadpool(byte[] publicKey, byte[] dataToVerify, byte[] signature)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (publicKey == null || publicKey.Length == 0)
            {
                throw new Exception("You must provide an allocated public key");
            }
            if (dataToVerify == null || dataToVerify.Length == 0)
            {
                throw new Exception("You must provide an allocated data to verify");
            }
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide an allocated signature ");
            }


            if (this._platform == OSPlatform.Linux)
            {
                bool result = DigitalSignatureLinuxWrapper.sha256_ed25519_digital_signature_verify_threadpool(publicKey, publicKey.Length, dataToVerify, dataToVerify.Length, signature, signature.Length);


                return result;
            }
            else
            {
                bool result = DigitalSignatureWindowsWrapper.sha256_ed25519_digital_signature_verify_threadpool(publicKey, publicKey.Length, dataToVerify, dataToVerify.Length, signature, signature.Length);


                return result;
            }
        }

        /// <summary>
        /// Verifies a SHA256 RSA Digital Signature.
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="dataToVerify"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>

        public bool VerifyRsa(string publicKey, byte[] dataToVerify, byte[] signature)
        {
            if (!RSAValidator.ValidateRsaPemKey(publicKey))
            {
                throw new Exception("You must provide a public key to verify with SHA512 RSA Digital Signature");
            }
            if (dataToVerify == null || dataToVerify.Length == 0)
            {
                throw new Exception("You must provide allocated data to verify");
            }
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide a allocated signature to verify");
            }


            if (this._platform == OSPlatform.Linux)
            {
                bool result = DigitalSignatureLinuxWrapper.sha_256_rsa_digital_signature_verify(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);


                return result;
            }
            else
            {
                bool result = DigitalSignatureWindowsWrapper.sha_256_rsa_digital_signature_verify(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);


                return result;
            }
        }

        /// <summary>
        /// Verifies a SHA256 RSA Digital Signature on the threadpool.
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="dataToVerify"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>

        public bool VerifyRsaThreadpool(string publicKey, byte[] dataToVerify, byte[] signature)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (!RSAValidator.ValidateRsaPemKey(publicKey))
            {
                throw new Exception("You must provide a public key to verify with SHA512 RSA Digital Signature");
            }
            if (dataToVerify == null || dataToVerify.Length == 0)
            {
                throw new Exception("You must provide allocated data to verify");
            }
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide a allocated signature to verify");
            }


            if (this._platform == OSPlatform.Linux)
            {
                bool result = DigitalSignatureLinuxWrapper.sha_256_rsa_digital_signature_verify_threadpool(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);


                return result;
            }
            else
            {
                bool result = DigitalSignatureWindowsWrapper.sha_256_rsa_digital_signature_verify_threadpool(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);


                return result;
            }
        }
    }
}
