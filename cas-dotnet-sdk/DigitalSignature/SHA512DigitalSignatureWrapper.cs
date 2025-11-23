using CasDotnetSdk.DigitalSignature.Linux;
using CasDotnetSdk.DigitalSignature.Types;
using CasDotnetSdk.DigitalSignature.Windows;
using CasDotnetSdk.Fodies;
using CasDotnetSdk.Helpers;
using CASHelpers;
using System;
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
        /// Creates a RSA Digital Signature using SHA512
        /// </summary>
        /// <param name="rsaKeySize"></param>
        /// <param name="dataToSign"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        /// 
        [BenchmarkSender]
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

            return new SHARSADigitalSignatureResult()
            {
                PrivateKey = privateKey,
                PublicKey = publicKey,
                Signature = signature
            };
        }

        /// <summary>
        /// Verifies a RSA Digital Signature using SHA512
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="dataToVerify"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        /// 
        [BenchmarkSender]
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
            bool result = (this._platform == OSPlatform.Linux) ?
                DigitalSignatureLinuxWrapper.sha_512_rsa_digital_signature_verify(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length) :
                DigitalSignatureWindowsWrapper.sha_512_rsa_digital_signature_verify(publicKey, dataToVerify, dataToVerify.Length, signature, signature.Length);

            return result;
        }
    }
}
