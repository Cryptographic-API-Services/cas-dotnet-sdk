using CasDotnetSdk.DigitalSignature.Linux;
using CasDotnetSdk.DigitalSignature.Types;
using CasDotnetSdk.DigitalSignature.Windows;
using CasDotnetSdk.Helpers;
using CASHelpers;
using System;
using System.Runtime.InteropServices;

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
            DateTime start = DateTime.UtcNow;
            DateTime end = DateTime.UtcNow;
            SHARSAStructDigitialSignatureResult result =
                (this._platform == OSPlatform.Linux) ?
                DigitalSignatureLinuxWrapper.sha_256_rsa_digital_signature(rsaKeySize, dataToSign, dataToSign.Length) :
                DigitalSignatureWindowsWrapper.sha_256_rsa_digital_signature(rsaKeySize, dataToSign, dataToSign.Length);
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

            DateTime start = DateTime.UtcNow;
            bool result = (this._platform == OSPlatform.Linux) ?
                DigitalSignatureLinuxWrapper.sha_256_rsa_digital_signature_verify(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length) :
                DigitalSignatureWindowsWrapper.sha_256_rsa_digital_signature_verify(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);
            DateTime end = DateTime.UtcNow;

            return result;
        }
    }
}
