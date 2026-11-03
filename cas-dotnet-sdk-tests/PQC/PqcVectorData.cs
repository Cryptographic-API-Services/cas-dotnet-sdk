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
                // The Wycheproof vectors are downloaded at build time (see the
                // FetchWycheproofVectors target in the test .csproj), not committed.
                string hint = fileName.StartsWith("wycheproof_", StringComparison.Ordinal)
                    ? " Wycheproof vectors are downloaded during the build: rebuild the test project with network access (and without -p:FetchWycheproofVectors=false)."
                    : string.Empty;
                throw new FileNotFoundException($"PQC test vector file not found: {path}.{hint}");
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

        public static string ToHex(byte[] bytes)
        {
            var sb = new System.Text.StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
            {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }
    }
}
