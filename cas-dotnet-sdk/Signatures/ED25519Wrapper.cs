﻿using CasDotnetSdk.Signatures.Linux;
using CasDotnetSdk.Signatures.Windows;
using CASHelpers;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Signatures
{
    public class ED25519Wrapper
    {
        private readonly OSPlatform _platform;

        public ED25519Wrapper()
        {
            this._platform = new OperatingSystemDeterminator().GetOperatingSystem();
        }

        public class Ed25519SignatureResult
        {
            public string Signature { get; set; }
            public string PublicKey { get; set; }
        }

        public class Ed25519ByteSignatureResult
        {
            public byte[] Signature { get; set; }
            public byte[] PublicKey { get; set; }
        }

        internal struct Ed25519SignatureStruct
        {
            public IntPtr Signature { get; set; }
            public IntPtr Public_Key { get; set; }
        }

        internal struct Ed25519KeyPairBytesResultStruct
        {
            public IntPtr key_pair { get; set; }
            public int length { get; set; }
        }

        internal struct Ed25519ByteSignatureResultStruct
        {
            public IntPtr signature_byte_ptr { get; set; }
            public int signature_length { get; set; }
            public IntPtr public_key { get; set; }
            public int public_key_length { get; set; }
        }

        public byte[] GetKeyPairBytes()
        {
            if (this._platform == OSPlatform.Linux)
            {
                Ed25519KeyPairBytesResultStruct resultStruct = ED25519LinuxWrapper.get_ed25519_key_pair_bytes();
                byte[] keyPairResult = new byte[resultStruct.length];
                Marshal.Copy(resultStruct.key_pair, keyPairResult, 0, resultStruct.length);
                ED25519LinuxWrapper.free_bytes(resultStruct.key_pair);
                return keyPairResult;
            }
            else
            {
                Ed25519KeyPairBytesResultStruct resultStruct = ED25519WindowsWrapper.get_ed25519_key_pair_bytes();
                byte[] keyPairResult = new byte[resultStruct.length];
                Marshal.Copy(resultStruct.key_pair, keyPairResult, 0, resultStruct.length);
                ED25519WindowsWrapper.free_bytes(resultStruct.key_pair);
                return keyPairResult;
            }
        }

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

            if (this._platform == OSPlatform.Linux)
            {
                Ed25519ByteSignatureResultStruct resultStruct = ED25519LinuxWrapper.sign_with_key_pair_bytes(keyBytes, keyBytes.Length, dataToSign, dataToSign.Length);
                byte[] publicKeyResult = new byte[resultStruct.public_key_length];
                Marshal.Copy(resultStruct.public_key, publicKeyResult, 0, resultStruct.public_key_length);
                ED25519LinuxWrapper.free_bytes(resultStruct.public_key);
                byte[] signatureResult = new byte[resultStruct.signature_length];
                Marshal.Copy(resultStruct.signature_byte_ptr, signatureResult, 0, resultStruct.signature_length);
                ED25519LinuxWrapper.free_bytes(resultStruct.signature_byte_ptr);
                return new Ed25519ByteSignatureResult()
                {
                    PublicKey = publicKeyResult,
                    Signature = signatureResult
                };
            }
            else
            {
                Ed25519ByteSignatureResultStruct resultStruct = ED25519WindowsWrapper.sign_with_key_pair_bytes(keyBytes, keyBytes.Length, dataToSign, dataToSign.Length);
                byte[] publicKeyResult = new byte[resultStruct.public_key_length];
                Marshal.Copy(resultStruct.public_key, publicKeyResult, 0, resultStruct.public_key_length);
                ED25519WindowsWrapper.free_bytes(resultStruct.public_key);
                byte[] signatureResult = new byte[resultStruct.signature_length];
                Marshal.Copy(resultStruct.signature_byte_ptr, signatureResult, 0, resultStruct.signature_length);
                ED25519WindowsWrapper.free_bytes(resultStruct.signature_byte_ptr);
                return new Ed25519ByteSignatureResult()
                {
                    PublicKey = publicKeyResult,
                    Signature = signatureResult
                };
            }
        }

        public bool VerifyBytes(byte[] keyPair, byte[] signature, byte[] dataToVerify)
        {
            if (keyPair?.Length == 0)
            {
                throw new Exception("You must provide allocated key pair data to Verify Bytes with ED25519-Dalek");
            }
            if (signature?.Length == 0)
            {
                throw new Exception("You must provide allocated key pair data to Verify Bytes with ED25519-Dalek");
            }
            if (dataToVerify?.Length == 0)
            {
                throw new Exception("You must provide allocated key pair data to Verify Bytes with ED25519-Dalek");
            }

            if (this._platform == OSPlatform.Linux)
            {
                return ED25519LinuxWrapper.verify_with_key_pair_bytes(keyPair, keyPair.Length, signature, signature.Length, dataToVerify, dataToVerify.Length);
            }
            else
            {
                return ED25519WindowsWrapper.verify_with_key_pair_bytes(keyPair, keyPair.Length, signature, signature.Length, dataToVerify, dataToVerify.Length);
            }
        }

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
            if (this._platform == OSPlatform.Linux)
            {
                return ED25519LinuxWrapper.verify_with_public_key_bytes(publicKey, publicKey.Length, signature, signature.Length, dataToVerify, dataToVerify.Length);
            }
            else
            {
                return ED25519WindowsWrapper.verify_with_public_key_bytes(publicKey, publicKey.Length, signature, signature.Length, dataToVerify, dataToVerify.Length);
            }
        }
    }
}