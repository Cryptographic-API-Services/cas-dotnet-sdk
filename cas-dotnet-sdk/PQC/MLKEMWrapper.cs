using CasCoreLib;
using CasDotnetSdk.Helpers;
using CasDotnetSdk.PQC.Types;

namespace CasDotnetSdk.PQC
{
    /// <summary>
    /// ML-KEM-1024 (FIPS 203) post-quantum key encapsulation mechanism. The holder of the
    /// public key is sent a ciphertext; both parties derive the same 32-byte shared secret.
    /// </summary>
    public unsafe class MLKEMWrapper
    {
        public MLKEMWrapper()
        {
        }

        /// <summary>
        /// Generates an ML-KEM-1024 secret (3168-byte decapsulation) and public
        /// (1568-byte encapsulation) key pair.
        /// </summary>
        public MLKemKeyPair GenerateKeyPair()
        {
            MlKemKeyPairResult result = NativeMethods.ml_kem_1024_generate_key_pair();
            return new MLKemKeyPair
            {
                SecretKey = NativeByteBuffer.CopyAndFree(result.secret_key_ptr, result.secret_key_length),
                PublicKey = NativeByteBuffer.CopyAndFree(result.public_key_ptr, result.public_key_length)
            };
        }

        /// <summary>
        /// Encapsulates to an ML-KEM-1024 public key, returning the ciphertext to send to the
        /// secret-key holder and the shared secret the sender derives locally.
        /// </summary>
        /// <param name="publicKey">The 1568-byte ML-KEM-1024 public (encapsulation) key.</param>
        public MLKemEncapsulateResult Encapsulate(byte[] publicKey)
        {
            fixed (byte* publicKeyPtr = NativePin.Of(publicKey))
            {
                MlKemEncapsulateResult result = NativeMethods.ml_kem_1024_encapsulate_shared_secret(publicKeyPtr, (nuint)publicKey.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "ML-KEM encapsulate");
                return new MLKemEncapsulateResult
                {
                    Ciphertext = NativeByteBuffer.CopyAndFree(result.ciphertext_ptr, result.ciphertext_length),
                    SharedSecret = NativeByteBuffer.CopyAndFree(result.shared_secret_ptr, result.shared_secret_length)
                };
            }
        }

        /// <summary>
        /// Decapsulates an ML-KEM-1024 <paramref name="ciphertext"/> with the secret key,
        /// returning the 32-byte shared secret.
        /// </summary>
        /// <param name="secretKey">The 3168-byte ML-KEM-1024 secret (decapsulation) key.</param>
        /// <param name="ciphertext">The 1568-byte ciphertext produced by <see cref="Encapsulate"/>.</param>
        public byte[] Decapsulate(byte[] secretKey, byte[] ciphertext)
        {
            fixed (byte* secretKeyPtr = NativePin.Of(secretKey))
            fixed (byte* ciphertextPtr = NativePin.Of(ciphertext))
            {
                MlKemDecapsulateResult result = NativeMethods.ml_kem_1024_decapsulate_shared_secret(secretKeyPtr, (nuint)secretKey.Length, ciphertextPtr, (nuint)ciphertext.Length);
                CasErrorHandler.ThrowIfError(result.error_code, "ML-KEM decapsulate");
                return NativeByteBuffer.CopyAndFree(result.shared_secret_ptr, result.shared_secret_length);
            }
        }
    }
}
