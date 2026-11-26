using System.Numerics;
using System.Security.Cryptography;
using CasDotnetSdk.Asymmetric;
using CasDotnetSdk.Helpers;
using Xunit;

namespace CasDotnetSdkTests.Nist
{
    /// <summary>
    /// NIST CAVP FIPS 186-3 RSA vectors (RSA2VS). Only SHA-256 with 2048- and 3072-bit moduli
    /// run (cas-lib rejects keys under 2048 bits and uses SHA-256 only); the rest are skipped:
    /// <list type="bullet">
    /// <item><c>SigGen15_186-3.txt</c> (the <c>.rsp</c> response file with the private exponent
    /// <c>d</c> added by NIST for testing): RSASSA-PKCS1-v1_5 is deterministic, so
    /// <see cref="RSAWrapper.Sign"/> must reproduce NIST's signature exactly.</item>
    /// <item><c>SigVer15_186-3.rsp</c> against <see cref="RSAWrapper.Verify"/>.</item>
    /// <item><c>SigVerPSS_186-3.rsp</c> against <see cref="RSAWrapper.VerifyPss"/>, for the
    /// vectors with a 32-byte salt: the SDK verifies PS256 with a 32-byte salt only.</item>
    /// </list>
    /// The vectors give a key as <c>n, e, d</c>; the SDK takes PEM (PKCS#8 private, PKCS#1
    /// public), so the private key is rebuilt by recovering <c>p, q</c> from <c>n, e, d</c>.
    /// </summary>
    public class NistRsaTests
    {
        private readonly RSAWrapper _wrapper = new RSAWrapper();

        [Fact]
        public void SignMatchesNistSigGen15Vectors()
        {
            int run = 0;
            int skipped = 0;
            var failures = new List<string>();
            foreach (RspRecord record in RspFile.Read("SigGen15_186-3.txt", "SHAAlg"))
            {
                if (!IsSupported(record))
                {
                    skipped++;
                    continue;
                }
                run++;

                BigInteger n = ToBigInteger(record["n"]);
                BigInteger e = ToBigInteger(record["e"]);
                BigInteger d = ToBigInteger(record["d"]);
                byte[] message = record.Bytes("Msg");
                byte[] expected = record.Bytes("S");

                byte[] signature = this._wrapper.Sign(ToPkcs8Pem(n, e, d), message);
                if (!signature.SequenceEqual(expected))
                {
                    failures.Add($"{record} signature mismatched");
                }
                else if (!this._wrapper.Verify(ToPkcs1PublicPem(n, e), message, signature))
                {
                    failures.Add($"{record} did not verify");
                }
            }

            NistVectors.AssertCounts("SigGen15_186-3.txt", 20, 60, run, skipped);
            Assert.True(failures.Count == 0, $"{failures.Count}/{run} NIST RSA SigGen15 vectors failed: {string.Join(", ", failures)}");
        }

        [Fact]
        public void VerifyMatchesNistSigVer15Vectors()
        {
            RunSigVer("SigVer15_186-3.rsp", _ => true, (publicKey, message, signature) => this._wrapper.Verify(publicKey, message, signature), 36, 6, 234);
        }

        [Fact]
        public void VerifyPssMatchesNistSigVerPssVectors()
        {
            // The SDK verifies PS256 with a 32-byte salt only.
            RunSigVer("SigVerPSS_186-3.rsp", record => record["SaltVal"].Length == 64, (publicKey, message, signature) => this._wrapper.VerifyPss(publicKey, message, signature), 18, 3, 252);
        }

        private static void RunSigVer(string fileName, Func<RspRecord, bool> include, Func<string, byte[], byte[], bool> verify, int expectedRun, int expectedPassing, int expectedSkipped)
        {
            int run = 0;
            int skipped = 0;
            int passing = 0;
            var failures = new List<string>();
            foreach (RspRecord record in RspFile.Read(fileName, "SHAAlg"))
            {
                if (!IsSupported(record) || !include(record))
                {
                    skipped++;
                    continue;
                }
                run++;

                bool expected = !record.Failed;
                string publicKey = ToPkcs1PublicPem(ToBigInteger(record["n"]), ToBigInteger(record["e"]));
                byte[] message = record.Bytes("Msg");
                byte[] signature = record.Bytes("S");

                bool actual;
                try
                {
                    actual = verify(publicKey, message, signature);
                }
                catch (CasException) when (!expected)
                {
                    actual = false;
                }
                if (actual != expected)
                {
                    failures.Add($"{record} (Result = {record["Result"]}) got {actual}");
                }
                passing += expected ? 1 : 0;
            }

            NistVectors.AssertCounts(fileName, expectedRun, expectedSkipped, run, skipped);
            Assert.Equal(expectedPassing, passing);
            Assert.True(failures.Count == 0, $"{failures.Count}/{run} NIST vectors from {fileName} failed: {string.Join(", ", failures)}");
        }

        // SHA-256 with a 2048- or 3072-bit modulus: cas-lib rejects keys under 2048 bits and
        // signs and verifies with SHA-256 only.
        private static bool IsSupported(RspRecord record)
        {
            return record["SHAAlg"] == "SHA256" && (record["mod"] == "2048" || record["mod"] == "3072");
        }

        private static BigInteger ToBigInteger(string hex)
        {
            return new BigInteger(Convert.FromHexString(hex.Length % 2 == 1 ? "0" + hex : hex), isUnsigned: true, isBigEndian: true);
        }

        private static string ToPkcs1PublicPem(BigInteger n, BigInteger e)
        {
            using RSA rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = n.ToByteArray(isUnsigned: true, isBigEndian: true),
                Exponent = e.ToByteArray(isUnsigned: true, isBigEndian: true),
            });
            return new string(PemEncoding.Write("RSA PUBLIC KEY", rsa.ExportRSAPublicKey()));
        }

        private static string ToPkcs8Pem(BigInteger n, BigInteger e, BigInteger d)
        {
            (BigInteger p, BigInteger q) = RecoverPrimes(n, e, d);
            int modulusBytes = n.ToByteArray(isUnsigned: true, isBigEndian: true).Length;
            int halfBytes = (modulusBytes + 1) / 2;
            using RSA rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = n.ToByteArray(isUnsigned: true, isBigEndian: true),
                Exponent = e.ToByteArray(isUnsigned: true, isBigEndian: true),
                D = Pad(d, modulusBytes),
                P = Pad(p, halfBytes),
                Q = Pad(q, halfBytes),
                DP = Pad(d % (p - 1), halfBytes),
                DQ = Pad(d % (q - 1), halfBytes),
                InverseQ = Pad(BigInteger.ModPow(q, p - 2, p), halfBytes),
            });
            return new string(PemEncoding.Write("PRIVATE KEY", rsa.ExportPkcs8PrivateKey()));
        }

        // The standard probabilistic factoring of n from (e, d) (NIST SP 800-56B Appendix C):
        // k = de - 1 = 2^t * r; for some g, g^(r * 2^i) is a non-trivial square root of 1 mod n.
        private static (BigInteger P, BigInteger Q) RecoverPrimes(BigInteger n, BigInteger e, BigInteger d)
        {
            BigInteger k = d * e - 1;
            BigInteger r = k;
            int t = 0;
            while (r.IsEven)
            {
                r >>= 1;
                t++;
            }

            for (int g = 2; g < 1000; g++)
            {
                BigInteger x = BigInteger.ModPow(g, r, n);
                for (int i = 0; i < t; i++)
                {
                    BigInteger y = BigInteger.ModPow(x, 2, n);
                    if (y.IsOne && x != BigInteger.One && x != n - 1)
                    {
                        BigInteger p = BigInteger.GreatestCommonDivisor(x - 1, n);
                        BigInteger q = n / p;
                        return p > q ? (p, q) : (q, p);
                    }
                    x = y;
                }
            }
            throw new InvalidOperationException("Could not factor the NIST RSA modulus from (n, e, d).");
        }

        private static byte[] Pad(BigInteger value, int length)
        {
            byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
            if (bytes.Length >= length)
            {
                return bytes;
            }
            byte[] padded = new byte[length];
            Buffer.BlockCopy(bytes, 0, padded, length - bytes.Length, bytes.Length);
            return padded;
        }
    }
}
