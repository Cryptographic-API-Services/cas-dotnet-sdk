using CasDotnetSdk.DigitalSignature.Linux;
using CasDotnetSdk.DigitalSignature.Types;
using CasDotnetSdk.DigitalSignature.Windows;
using CasDotnetSdk.Helpers;
using CasDotnetSdk.Http;
using CASHelpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.DigitalSignature
{
    public class SHA512DigitalSignatureWrapper : BaseWrapper, IDigitalSignature
    {

        /// <summary>
        /// A wrapper class for creating Digital Signatures using SHA512 (ED25519-Dalek and RSA)
        /// </summary>
        public SHA512DigitalSignatureWrapper()
        {

        }

        /// <summary>
        /// Creates an ED25519 Digital Signature using SHA512
        /// </summary>
        /// <param name="dataToSign"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public SHAED25519DalekDigitialSignatureResult CreateED25519(byte[] dataToSign)
        {
            if (dataToSign == null || dataToSign.Length == 0)
            {
                throw new Exception("You must provide an allocated data array to create a digital signature");
            }

            DateTime start = DateTime.UtcNow;
            SHAED25519DalekStructDigitalSignatureResult signatureResult = (this._platform == OSPlatform.Linux) ? 
                DigitalSignatureLinuxWrapper.sha512_ed25519_digital_signature(dataToSign, dataToSign.Length) : 
                DigitalSignatureWindowsWrapper.sha512_ed25519_digital_signature(dataToSign, dataToSign.Length);
            byte[] publicKey = new byte[signatureResult.public_key_length];
            Marshal.Copy(signatureResult.public_key, publicKey, 0, signatureResult.public_key_length);
            byte[] signature = new byte[signatureResult.signature_length];
            Marshal.Copy(signatureResult.signature_raw_ptr, signature, 0, signatureResult.signature_length);
            FreeMemoryHelper.FreeBytesMemory(signatureResult.public_key);
            FreeMemoryHelper.FreeBytesMemory(signatureResult.signature_raw_ptr);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
            return new SHAED25519DalekDigitialSignatureResult()
            {
                PublicKey = publicKey,
                Signature = signature,
            };
        }

        /// <summary>
        /// Creates a RSA Digital Signature using SHA512
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

            DateTime start = DateTime.UtcNow;
            SHARSAStructDigitialSignatureResult result = (this._platform == OSPlatform.Linux) ? 
                DigitalSignatureLinuxWrapper.sha_512_rsa_digital_signature(rsaKeySize, dataToSign, dataToSign.Length) : 
                DigitalSignatureWindowsWrapper.sha_512_rsa_digital_signature(rsaKeySize, dataToSign, dataToSign.Length);
            string publicKey = Marshal.PtrToStringAnsi(result.public_key);
            string privateKey = Marshal.PtrToStringAnsi(result.private_key);
            byte[] signature = new byte[result.length];
            Marshal.Copy(result.signature, signature, 0, result.length);
            FreeMemoryHelper.FreeCStringMemory(result.public_key);
            FreeMemoryHelper.FreeCStringMemory(result.private_key);
            FreeMemoryHelper.FreeBytesMemory(result.signature);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
            return new SHARSADigitalSignatureResult()
            {
                PrivateKey = privateKey,
                PublicKey = publicKey,
                Signature = signature
            };
        }



        /// <summary>
        /// Verifies a ED25519 Digital Signature using SHA512
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
                throw new Exception("You must provide a allocated array for the public to verify a digital signature");
            }
            if (dataToVerify == null || dataToVerify.Length == 0)
            {
                throw new Exception("You must provde an allocated array for the data to verify to verify a digital signature");
            }
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide an allocated array for the signature to verfiy a digital signature");
            }

            DateTime start = DateTime.UtcNow;
            bool result = (this._platform == OSPlatform.Linux) ? 
                DigitalSignatureLinuxWrapper.sha512_ed25519_digital_signature_verify(publicKey, publicKey.Length, dataToVerify, dataToVerify.Length, signature, signature.Length) : 
                DigitalSignatureWindowsWrapper.sha512_ed25519_digital_signature_verify(publicKey, publicKey.Length, dataToVerify, dataToVerify.Length, signature, signature.Length);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
            return result;
        }

        /// <summary>
        /// Verifies a RSA Digital Signature using SHA512
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

            DateTime start = DateTime.UtcNow;
            bool result = (this._platform == OSPlatform.Linux) ?
                DigitalSignatureLinuxWrapper.sha_512_rsa_digital_signature_verify(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length) :
                DigitalSignatureWindowsWrapper.sha_512_rsa_digital_signature_verify(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);
            DateTime end = DateTime.UtcNow;
            this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.DigitalSignature, nameof(SHA512DigitalSignatureWrapper));
            return result;
        }
    }
}
