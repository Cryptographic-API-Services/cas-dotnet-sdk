using System.Text;

namespace CasDotnetSdkBenchmarks
{
    /// <summary>
    /// Deterministic inputs, so every run (and every machine) benchmarks the same bytes.
    /// </summary>
    internal static class Payloads
    {
        public const int OneKiB = 1024;
        public const int OneMiB = 1024 * 1024;

        public const string Password = "correct horse battery staple";

        /// <summary>Pseudo-random, incompressible bytes.</summary>
        public static byte[] RandomBytes(int length, int seed = 42)
        {
            var bytes = new byte[length];
            new System.Random(seed).NextBytes(bytes);
            return bytes;
        }

        /// <summary>Text-like bytes that compress roughly like a log or JSON file.</summary>
        public static byte[] Compressible(int length, int seed = 42)
        {
            string[] words = { "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "{\"id\":", "\"name\":", "}," };
            var random = new System.Random(seed);
            var builder = new StringBuilder(length + 16);
            while (builder.Length < length)
            {
                builder.Append(words[random.Next(words.Length)]).Append(' ').Append(random.Next(1000)).Append('\n');
            }
            return Encoding.UTF8.GetBytes(builder.ToString(0, length));
        }
    }
}
