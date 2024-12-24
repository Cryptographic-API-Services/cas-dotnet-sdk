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
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                HmacSignByteResult signed = HmacLinuxWrapper.hmac_sign_bytes(key, key.Length, message, message.Length);
                byte[] result = new byte[signed.length];
                Marshal.Copy(signed.result_bytes_ptr, result, 0, signed.length);
                FreeMemoryHelper.FreeBytesMemory(signed.result_bytes_ptr);
                DateTime end = DateTime.UtcNow;
                return result;
            }
            else
            {
                HmacSignByteResult signed = HmacWindowsWrapper.hmac_sign_bytes(key, key.Length, message, message.Length);
                byte[] result = new byte[signed.length];
                Marshal.Copy(signed.result_bytes_ptr, result, 0, signed.length);
                FreeMemoryHelper.FreeBytesMemory(signed.result_bytes_ptr);
                DateTime end = DateTime.UtcNow;
                return result;
            }
        }

        /// <summary>
        /// Signs a message using the HMAC algorithm on the threadpool.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public byte[] HmacSignBytesThreadpool(byte[] key, byte[] message)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (key == null || key.Length == 0)
            {
                throw new Exception("You must provide a key to sign with HMAC");
            }
            if (message == null || message.Length == 0)
            {
                throw new Exception("You must provide a message to sign with HMAC");
            }
            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                HmacSignByteResult signed = HmacLinuxWrapper.hmac_sign_bytes_threadpool(key, key.Length, message, message.Length);
                byte[] result = new byte[signed.length];
                Marshal.Copy(signed.result_bytes_ptr, result, 0, signed.length);
                FreeMemoryHelper.FreeBytesMemory(signed.result_bytes_ptr);
                DateTime end = DateTime.UtcNow;
                return result;
            }
            else
            {
                HmacSignByteResult signed = HmacWindowsWrapper.hmac_sign_bytes_threadpool(key, key.Length, message, message.Length);
                byte[] result = new byte[signed.length];
                Marshal.Copy(signed.result_bytes_ptr, result, 0, signed.length);
                FreeMemoryHelper.FreeBytesMemory(signed.result_bytes_ptr);
                DateTime end = DateTime.UtcNow;
                return result;
            }
        }

        /// <summary>
        /// Verifies a message using the HMAC algorithm.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="message"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
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

            DateTime start = DateTime.UtcNow;
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide a signature to verify with HMAC");
            }
            if (this._platform == OSPlatform.Linux)
            {
                bool result = HmacLinuxWrapper.hmac_verify_bytes(key, key.Length, message, message.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                return result;
            }
            else
            {
                bool result = HmacWindowsWrapper.hmac_verify_bytes(key, key.Length, message, message.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                return result;
            }
        }

        /// <summary>
        /// Verifies a message using the HMAC algorithm on the threadpool.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="message"></param>
        /// <param name="signature"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public bool HmacVerifyBytesThreadpool(byte[] key, byte[] message, byte[] signature)
        {
            if (!CASConfiguration.IsThreadingEnabled)
            {
                throw new Exception("You do not have the product subscription to work with the thread pool featues");
            }

            if (key == null || key.Length == 0)
            {
                throw new Exception("You must provide a key to verify with HMAC");
            }
            if (message == null || message.Length == 0)
            {
                throw new Exception("You must provide a message to verify with HMAC");
            }

            DateTime start = DateTime.UtcNow;
            if (signature == null || signature.Length == 0)
            {
                throw new Exception("You must provide a signature to verify with HMAC");
            }
            if (this._platform == OSPlatform.Linux)
            {
                bool result = HmacLinuxWrapper.hmac_verify_bytes_threadpool(key, key.Length, message, message.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                return result;
            }
            else
            {
                bool result = HmacWindowsWrapper.hmac_verify_bytes_threadpool(key, key.Length, message, message.Length, signature, signature.Length);
                DateTime end = DateTime.UtcNow;
                return result;
            }
        }
    }
}