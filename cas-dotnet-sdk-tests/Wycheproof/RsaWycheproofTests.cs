using System;
using System.Collections.Generic;
using CasDotnetSdk.Asymmetric;
using CasDotnetSdkTests.PQC;
using Xunit;

namespace CasDotnetSdkTests.Wycheproof
{
    /// <summary>
    /// Project Wycheproof RSA signature-verification vectors: RSASSA-PKCS1-v1_5 with SHA-256
    /// against <see cref="RSAWrapper.Verify"/> and RSASSA-PSS with SHA-256, MGF1-SHA-256 and a
    /// 32-byte salt against <see cref="RSAWrapper.VerifyPss"/>, for 2048-, 3072- and 4096-bit keys.
    /// The SDK's verify API rejects an empty message, so empty-message vectors are skipped
    /// (counted). "acceptable" vectors may go either way, so only "valid" and "invalid" are asserted.
    /// </summary>
    public class RsaWycheproofTests
    {
        private readonly RSAWrapper _wrapper = new RSAWrapper();

        [Theory]
        [InlineData("wycheproof_rsa_pkcs1_2048_sha256.json")]
        [InlineData("wycheproof_rsa_pkcs1_3072_sha256.json")]
        [InlineData("wycheproof_rsa_pkcs1_4096_sha256.json")]
        public void WycheproofRsaPkcs1Sha256VerificationVectors(string file)
        {
            RunVectors(file, "RsassaPkcs1Verify", (publicKey, msg, sig) => _wrapper.Verify(publicKey, msg, sig));
        }

        [Theory]
        [InlineData("wycheproof_rsa_pss_2048_sha256_mgf1_32.json")]
        [InlineData("wycheproof_rsa_pss_3072_sha256_mgf1_32.json")]
        [InlineData("wycheproof_rsa_pss_4096_sha256_mgf1_32.json")]
        public void WycheproofRsaPssSha256VerificationVectors(string file)
        {
            RunVectors(file, "RsassaPssVerify", (publicKey, msg, sig) => _wrapper.VerifyPss(publicKey, msg, sig));
        }

        private static void RunVectors(string file, string expectedType, Func<string, byte[], byte[], bool> verify)
        {
            var root = PqcVectorData.Load(file);
            int count = 0;
            int skippedEmpty = 0;
            var failures = new List<string>();

            foreach (var group in root.GetProperty("testGroups").EnumerateArray())
            {
                Assert.Equal(expectedType, group.GetProperty("type").GetString());
                Assert.Equal("SHA-256", group.GetProperty("sha").GetString());
                if (expectedType == "RsassaPssVerify")
                {
                    Assert.Equal("SHA-256", group.GetProperty("mgfSha").GetString());
                    Assert.Equal(32, group.GetProperty("sLen").GetInt32());
                }

                // publicKeyAsn is the PKCS#1 RSAPublicKey DER, the format GetKeyPair returns as PEM.
                string publicKey = ToPkcs1Pem(PqcVectorData.Hex(group.GetProperty("publicKeyAsn").GetString()!));

                foreach (var test in group.GetProperty("tests").EnumerateArray())
                {
                    int tcId = test.GetProperty("tcId").GetInt32();
                    string msgHex = test.GetProperty("msg").GetString()!;
                    string result = test.GetProperty("result").GetString()!;

                    // The public verify API rejects empty input.
                    if (msgHex.Length == 0)
                    {
                        skippedEmpty++;
                        continue;
                    }

                    byte[] msg = PqcVectorData.Hex(msgHex);
                    byte[] sig = PqcVectorData.Hex(test.GetProperty("sig").GetString()!);

                    bool verified;
                    try
                    {
                        // An empty signature or a rejected key (e.g. under 2048 bits) throws
                        // instead of returning false; both count as a rejection.
                        verified = verify(publicKey, msg, sig);
                    }
                    catch
                    {
                        verified = false;
                    }
                    count++;

                    if (result == "valid" && !verified)
                    {
                        failures.Add($"tcId={tcId} valid signature rejected");
                    }
                    else if (result == "invalid" && verified)
                    {
                        failures.Add($"tcId={tcId} invalid signature accepted");
                    }
                }
            }

            Assert.True(count > 0, $"No RSA vectors were loaded from {file}.");
            Assert.True(failures.Count == 0, $"{failures.Count}/{count} RSA vectors in {file} failed (skippedEmpty={skippedEmpty}): {string.Join("; ", failures)}");
        }

        private static string ToPkcs1Pem(byte[] der)
        {
            // RFC 7468 PEM: base64 in 64-character lines.
            string base64 = Convert.ToBase64String(der);
            var pem = new System.Text.StringBuilder("-----BEGIN RSA PUBLIC KEY-----\n");
            for (int i = 0; i < base64.Length; i += 64)
            {
                pem.Append(base64, i, Math.Min(64, base64.Length - i)).Append('\n');
            }
            return pem.Append("-----END RSA PUBLIC KEY-----\n").ToString();
        }
    }
}
