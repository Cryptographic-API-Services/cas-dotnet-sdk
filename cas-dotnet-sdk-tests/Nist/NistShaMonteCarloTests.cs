using CasDotnetSdk.Hashers;
using Xunit;

namespace CasDotnetSdkTests.Nist
{
    /// <summary>
    /// NIST CAVP Monte Carlo tests for SHA-256/512 (SHAVS) and SHA3-256/512 (SHA3VS). Each of the
    /// 100 checkpoints chains 1,000 hashes of the previous outputs, so a single wrong byte or
    /// length-handling bug anywhere in the chain changes every later checkpoint.
    /// </summary>
    public class NistShaMonteCarloTests
    {
        private const int Checkpoints = 100;

        [Theory]
        [InlineData("SHA256Monte.rsp", 256)]
        [InlineData("SHA512Monte.rsp", 512)]
        public void Sha2MatchesNistMonteCarloVectors(string fileName, int bits)
        {
            var wrapper = new SHA2Wrapper();
            Func<byte[]?, byte[]> hash = bits == 256 ? wrapper.Hash256 : wrapper.Hash512;
            List<RspRecord> records = RspFile.Read(fileName, "COUNT");
            NistVectors.AssertCounts(fileName, Checkpoints, 0, records.Count, 0);

            // SHAVS 6.4: MD0 = MD1 = MD2 = Seed; MDi = SHA(MDi-3 || MDi-2 || MDi-1) for
            // i = 3..1002; the checkpoint is MD1002, which seeds the next checkpoint.
            byte[] seed = records[0].Bytes("Seed");
            foreach (RspRecord record in records)
            {
                byte[] a = seed, b = seed, c = seed;
                for (int i = 3; i < 1003; i++)
                {
                    byte[] next = hash(Concat(a, b, c));
                    a = b;
                    b = c;
                    c = next;
                }
                Assert.True(record.Bytes("MD").SequenceEqual(c), $"{fileName} {record} mismatched");
                seed = c;
            }
        }

        [Theory]
        [InlineData("SHA3_256Monte.rsp", 256)]
        [InlineData("SHA3_512Monte.rsp", 512)]
        public void Sha3MatchesNistMonteCarloVectors(string fileName, int bits)
        {
            var wrapper = new SHAWrapper();
            Func<byte[]?, byte[]> hash = bits == 256 ? wrapper.Hash256 : wrapper.Hash512;
            List<RspRecord> records = RspFile.Read(fileName, "COUNT");
            NistVectors.AssertCounts(fileName, Checkpoints, 0, records.Count, 0);

            // SHA3VS 6.2.3: MD0 = Seed; MDi = SHA3(MDi-1) for i = 1..1000; the checkpoint is
            // MD1000, which seeds the next checkpoint.
            byte[] md = records[0].Bytes("Seed");
            foreach (RspRecord record in records)
            {
                for (int i = 0; i < 1000; i++)
                {
                    md = hash(md);
                }
                Assert.True(record.Bytes("MD").SequenceEqual(md), $"{fileName} {record} mismatched");
            }
        }

        private static byte[] Concat(byte[] a, byte[] b, byte[] c)
        {
            byte[] result = new byte[a.Length + b.Length + c.Length];
            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
            Buffer.BlockCopy(c, 0, result, a.Length + b.Length, c.Length);
            return result;
        }
    }
}
