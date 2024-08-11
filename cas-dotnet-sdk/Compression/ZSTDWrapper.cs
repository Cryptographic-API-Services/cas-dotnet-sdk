using CasDotnetSdk.Compression.Linux;
using CasDotnetSdk.Compression.Types;
using CasDotnetSdk.Compression.Windows;
using CasDotnetSdk.Helpers;
using CASHelpers.Types.HttpResponses.BenchmarkAPI;
using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace CasDotnetSdk.Compression
{
    public class ZSTDWrapper : BaseWrapper
    {
        public ZSTDWrapper()
        {
            
        }

        /// <summary>
        /// Datas to the byte array to compress and the level of encryption.
        /// Zstandard (zstd) supports 22 compression levels, ranging from -22 to 22. Lower levels, such as 1–9, 
        /// are faster but result in larger file sizes, while higher levels, such as 10–22, provide better compression ratios.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="level"></param>
        /// <returns></returns>
        public byte[] Compress(byte[] data, int level)
        {
            if (data == null || data.Length == 0)
            {
                throw new Exception("Must pass an allocated data array to ZSTD Compression");
            }
            if (level < -22 || level > 22)
            {
                throw new Exception("Please pass in a valid level for ZSTD Compression");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                ZSTDResult compressResult = ZSTDLinuxWrapper.compress(data, data.Length, level);
                byte[] result = new byte[compressResult.length];
                Marshal.Copy(compressResult.data, result, 0, compressResult.length);
                FreeMemoryHelper.FreeBytesMemory(compressResult.data);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Compression, nameof(ZSTDWrapper));
                return result;
            }
            else
            {
                ZSTDResult compressResult = ZSTDWindowsWrapper.compress(data, data.Length, level);
                byte[] result = new byte[compressResult.length];
                Marshal.Copy(compressResult.data, result, 0, compressResult.length);
                FreeMemoryHelper.FreeBytesMemory(compressResult.data);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Compression, nameof(ZSTDWrapper));
                return result;
            }
        }

        /// <summary>
        /// Datas to the byte array to compress and the level of encryption on the threadpool.
        /// Zstandard (zstd) supports 22 compression levels, ranging from -22 to 22. Lower levels, such as 1–9, 
        /// are faster but result in larger file sizes, while higher levels, such as 10–22, provide better compression ratios.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="level"></param>
        /// <returns></returns>
        public byte[] CompressThreadpool(byte[] data, int level)
        {
            if (data == null || data.Length == 0)
            {
                throw new Exception("Must pass an allocated data array to ZSTD Compression");
            }
            if (level < -22 || level > 22)
            {
                throw new Exception("Please pass in a valid level for ZSTD Compression");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                ZSTDResult compressResult = ZSTDLinuxWrapper.compress_threadpool(data, data.Length, level);
                byte[] result = new byte[compressResult.length];
                Marshal.Copy(compressResult.data, result, 0, compressResult.length);
                FreeMemoryHelper.FreeBytesMemory(compressResult.data);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Compression, nameof(ZSTDWrapper));
                return result;
            }
            else
            {
                ZSTDResult compressResult = ZSTDWindowsWrapper.compress_threadpool(data, data.Length, level);
                byte[] result = new byte[compressResult.length];
                Marshal.Copy(compressResult.data, result, 0, compressResult.length);
                FreeMemoryHelper.FreeBytesMemory(compressResult.data);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Compression, nameof(ZSTDWrapper));
                return result;
            }
        }

        /// <summary>
        /// Decompresses and previosuly compressed byte array with ZSTD.
        /// No level is required to decompress.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public byte[] Decompress(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                throw new Exception("Must pass in an allocated array of data to decompress");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                ZSTDResult decompressResult = ZSTDLinuxWrapper.decompress(data, data.Length);
                byte[] result = new byte[decompressResult.length];
                Marshal.Copy(decompressResult.data, result, 0, decompressResult.length);
                FreeMemoryHelper.FreeBytesMemory(decompressResult.data);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Compression, nameof(ZSTDWrapper));
                return result;
            }
            else
            {
                ZSTDResult decompressResult = ZSTDWindowsWrapper.decompress(data, data.Length);
                byte[] result = new byte[decompressResult.length];
                Marshal.Copy(decompressResult.data, result, 0, decompressResult.length);
                FreeMemoryHelper.FreeBytesMemory(decompressResult.data);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Compression, nameof(ZSTDWrapper));
                return result;
            }
        }

        /// <summary>
        /// Decompresses and previosuly compressed byte array with ZSTD on the threadpool.
        /// No level is required to decompress.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public byte[] DecompressThreadpool(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                throw new Exception("Must pass in an allocated array of data to decompress");
            }

            DateTime start = DateTime.UtcNow;
            if (this._platform == OSPlatform.Linux)
            {
                ZSTDResult decompressResult = ZSTDLinuxWrapper.decompress_threadpool(data, data.Length);
                byte[] result = new byte[decompressResult.length];
                Marshal.Copy(decompressResult.data, result, 0, decompressResult.length);
                FreeMemoryHelper.FreeBytesMemory(decompressResult.data);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Compression, nameof(ZSTDWrapper));
                return result;
            }
            else
            {
                ZSTDResult decompressResult = ZSTDWindowsWrapper.decompress_threadpool(data, data.Length);
                byte[] result = new byte[decompressResult.length];
                Marshal.Copy(decompressResult.data, result, 0, decompressResult.length);
                FreeMemoryHelper.FreeBytesMemory(decompressResult.data);
                DateTime end = DateTime.UtcNow;
                this._sender.SendNewBenchmarkMethod(MethodBase.GetCurrentMethod().Name, start, end, BenchmarkMethodType.Compression, nameof(ZSTDWrapper));
                return result;
            }
        }
    }
}
