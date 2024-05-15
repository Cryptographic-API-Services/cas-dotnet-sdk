namespace CasDotnetSdk.Hybrid.Types
{
    public class AESRSAHybridEncryptResult
    {
        public int AesType { get; set; }
        public byte[] AesNonce { get; set; }
        public byte[] CipherText { get; set; }
        public byte[] EncryptedAesKey { get; set; }
    }
}
