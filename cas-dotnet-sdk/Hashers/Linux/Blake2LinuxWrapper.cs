﻿using System.Runtime.InteropServices;
using CasDotnetSdk.Hashers.Types;

namespace CasDotnetSdk.Hashers.Linux
{
    internal static class Blake2LinuxWrapper
    {
        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Blake2HashByteResult blake2_512_bytes(byte[] toHash, int toHashLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Blake2HashByteResult blake2_512_bytes_threadpool(byte[] toHash, int toHashLength);


        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Blake2HashByteResult blake2_256_bytes(byte[] toHash, int toHashLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern Blake2HashByteResult blake2_256_bytes_threadpool(byte[] toHash, int toHashLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern bool blake2_256_bytes_verify(byte[] hashedData, int hashedDatLength, byte[] toCompare, int toCompareLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern bool blake2_256_bytes_verify_threadpool(byte[] hashedData, int hashedDatLength, byte[] toCompare, int toCompareLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern bool blake2_512_bytes_verify(byte[] hashedData, int hashedDatLength, byte[] toCompare, int toCompareLength);

        [DllImport("Contents/libcas_core_lib.so")]
        public static extern bool blake2_512_bytes_verify_threadpool(byte[] hashedData, int hashedDatLength, byte[] toCompare, int toCompareLength);
    }
}
