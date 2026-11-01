using System;
using System.IO;
using System.Text.Json;

namespace CasDotnetSdkTests.PQC
{
    /// <summary>
    /// Loads the NIST ACVP (FIPS 203/204) and Project Wycheproof known-answer test
    /// vector files that are copied next to the test assembly from <c>PQC/Data</c>.
    /// </summary>
    internal static class PqcVectorData
    {
        public static JsonElement Load(string fileName)
        {
            string path = Path.Combine(AppContext.BaseDirectory, "PQC", "Data", fileName);
            if (!File.Exists(path))
            {
                throw new FileNotFoundException($"PQC test vector file not found: {path}");
            }
            byte[] bytes = File.ReadAllBytes(path);
            return JsonDocument.Parse(bytes).RootElement.Clone();
        }

        public static byte[] Hex(string hex)
        {
            if (string.IsNullOrEmpty(hex))
            {
                return Array.Empty<byte>();
            }
            int len = hex.Length / 2;
            byte[] result = new byte[len];
            for (int i = 0; i < len; i++)
            {
                result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return result;
        }
    }
}
