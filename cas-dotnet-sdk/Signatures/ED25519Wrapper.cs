using CasDotnetSdk.Fodies;
using CasDotnetSdk.Helpers;
using CasDotnetSdk.Signatures.Linux;
using CasDotnetSdk.Signatures.Types;
using CasDotnetSdk.Signatures.Windows;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Signatures
{
    public class ED25519Wrapper : BaseWrapper
    {

        public ED25519Wrapper()
        {
        }

        /// <summary>
        /// Generates and public and private key pair non split in bytes for ED25519-Dalek.
        /// </summary>
        /// <returns></returns>
        /// 
        [BenchmarkSender]
        public Ed25519KeyPairResult GetKeyPair()
        {
            
            Ed25519KeyPairBytesResultStruct resultStruct = (this._platform == OSPlatform.Linux) ?
                ED25519LinuxWrapper.get_ed25519_key_pair_bytes() :
                ED25519WindowsWrapper.get_ed25519_key_pair_bytes();
            byte[] signingKey = new byte[resultStruct.signing_key_length];
            Marshal.Copy(resultStruct.signing_key, signingKey, 0, resultStruct.signing_key_length);
            byte[] verifyingKey = new byte[resultStruct.verifying_key_length];
            Marshal.Copy(resultStruct.verifying_key, verifyingKey, 0, resultStruct.verifying_key_length);
            FreeMemoryHelper.FreeBytesMemory(resultStruct.verifying_key);
            FreeMemoryHelper.FreeBytesMemory(resultStruct.signing_key);
            

            return new Ed25519KeyPairResult()
            {
                SigningKey = signingKey,
                VerifyingKey = verifyingKey
            };
        }

        /// <summary>
        /// Signs data with a key pair in bytes for ED25519-Dalek.
        /// </summary>
        /// <param name="keyBytes"></param>
        /// <param name="dataToSign"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        /// 
        [BenchmarkSender]
        public Ed25519ByteSignatureResult SignBytes(byte[] keyBytes, byte[] dataToSign)
        {
            if (keyBytes == null || keyBytes.Length == 0)
            {
                throw new Exception("You must provide an array allocated with key data to Sign with ED25519-Dalek");
            }
            if (dataToSign == null || dataToSign.Length == 0)
            {
                throw new Exception("You must provide an array allocated with data to Sign with ED25519-Dalek");
            }

            
            Ed25519ByteSignatureResultStruct resultStruct = (this._platform == OSPlatform.Linux) ?
                ED25519LinuxWrapper.sign_with_key_pair_bytes(keyBytes, keyBytes.Length, dataToSign, dataToSign.Length) :
                ED25519WindowsWrapper.sign_with_key_pair_bytes(keyBytes, keyBytes.Length, dataToSign, dataToSign.Length);
            byte[] publicKeyResult = new byte[resultStruct.public_key_length];
            Marshal.Copy(resultStruct.public_key, publicKeyResult, 0, resultStruct.public_key_length);
            FreeMemoryHelper.FreeBytesMemory(resultStruct.public_key);
            byte[] signatureResult = new byte[resultStruct.signature_length];
            Marshal.Copy(resultStruct.signature_byte_ptr, signatureResult, 0, resultStruct.signature_length);
            FreeMemoryHelper.FreeBytesMemory(resultStruct.signature_byte_ptr);
            

            return new Ed25519ByteSignatureResult()
            {
                PublicKey = publicKeyResult,
                Signature = signatureResult
            };
        }

        /// <summary>
        /// Verifys data with a key pair in bytes for ED25519-Dalek.
        /// </summary>
        /// <param name="keyPair"></param>
        /// <param name="signature"></param>
        /// <param name="dataToVerify"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        /// 
        [BenchmarkSender]
        public bool VerifyBytes(byte[] keyPair, byte[] signature, byte[] dataToVerify)
        {
            if (keyPair?.Length == 0)
            {
                throw new Exception("You must provide allocated key pair data to Verify Bytes with ED25519-Dalek");
            }
            if (signature?.Length == 0)
            {
                throw new Exception("You must provide allocated signature data to Verify Bytes with ED25519-Dalek");
            }
            if (dataToVerify?.Length == 0)
            {
                throw new Exception("You must provide allocated data to Verify with ED25519-Dalek");
            }

            
            bool result = (this._platform == OSPlatform.Linux) ?
                ED25519LinuxWrapper.verify_with_key_pair_bytes(keyPair, keyPair.Length, signature, signature.Length, dataToVerify, dataToVerify.Length) :
                ED25519WindowsWrapper.verify_with_key_pair_bytes(keyPair, keyPair.Length, signature, signature.Length, dataToVerify, dataToVerify.Length);
            

            return result;
        }

        /// <summary>
        /// Verifies with a public key in bytes for ED25519-Dalek.
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="signature"></param>
        /// <param name="dataToVerify"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        /// 
        [BenchmarkSender]
        public bool VerifyWithPublicKeyBytes(byte[] publicKey, byte[] signature, byte[] dataToVerify)
        {
            if (publicKey?.Length == 0)
            {
                throw new Exception("You must provide allocated data for the public key to verify with ED25519-Dalek");
            }
            if (signature?.Length == 0)
            {
                throw new Exception("You must provide allocated data for the signature to verify with ED25519-Dalek");
            }
            if (dataToVerify?.Length == 0)
            {
                throw new Exception("You must provide allocated data to verify for the signature to verify with ED25519-Dalek");
            }
            
            bool result = (this._platform == OSPlatform.Linux) ?
                ED25519LinuxWrapper.verify_with_public_key_bytes(publicKey, publicKey.Length, signature, signature.Length, dataToVerify, dataToVerify.Length) :
                ED25519WindowsWrapper.verify_with_public_key_bytes(publicKey, publicKey.Length, signature, signature.Length, dataToVerify, dataToVerify.Length);
            

            return result;
        }
    }
}