using CasDotnetSdk.Fodies;
using CasDotnetSdk.Hashers.Linux;
using CasDotnetSdk.Hashers.Types;
using CasDotnetSdk.Hashers.Windows;
using CasDotnetSdk.Helpers;
using System;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Hashers
{
    public class HmacWrapper : BaseWrapper
    {


        /// <summary>
        /// A wrapper class for the HMAC hashing algorithm.
        /// </summary>
        public HmacWrapper()
        {

        }

        /// <summary>
        /// Signs a message using the HMAC algorithm.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        /// 
        [BenchmarkSender]
        public byte[] HmacSignBytes(byte[] key, byte[] message)
        {
            if (key == null || key.Length == 0)
            {
                throw new Exception("You must provide a key to sign with HMAC");
            }
            if (message == null || message.Length == 0)
            {
                throw new Exception("You must provide a message to sign with HMAC");
            }

            HmacSignByteResult signed = (this._platform == OSPlatform.Linux) ?
                HmacLinuxWrapper.hmac_sign_bytes(key, key.Length, message, message.Length) :
                HmacWindowsWrapper.hmac_sign_bytes(key, key.Length, message, message.Length);
            byte[] result = new byte[signed.length];
            Marshal.Copy(signed.result_bytes_ptr, result, 0, signed.length);
            FreeMemoryHelper.FreeBytesMemory(signed.result_bytes_ptr);


            return result;
        }

        /// <summary>
        /// Verifies a message using the HMAC algorithm.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="message"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        /// 
        [BenchmarkSender]
        public bool HmacVerifyBytes(byte[] key, byte[] message, byte[] signature)
        {
            if (key == null || key.Length == 0)
            {
                throw new Exception("You must provide a key to verify with HMAC");
            }
            if (message == null || message.Length == 0)
            {
                throw new Exception("You must provide a message to verify with HMAC");
            }
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide a signature to verify with HMAC");
            }

            bool result = (this._platform == OSPlatform.Linux) ?
                HmacLinuxWrapper.hmac_verify_bytes(key, key.Length, message, message.Length, signature, signature.Length) :
                HmacWindowsWrapper.hmac_verify_bytes(key, key.Length, message, message.Length, signature, signature.Length);


            return result;
        }
    }
}