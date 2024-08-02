using CasDotnetSdk.Hashers.Types;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CasDotnetSdk.Compression
{
    public class ZSTDWrapper
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

        }

        /// <summary>
        /// Decompresses and previosuly compressed byte array with ZSTD.
        /// No level is required to decompress.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public byte[] Decompress(byte[] data)
        {

        }
    }
}
