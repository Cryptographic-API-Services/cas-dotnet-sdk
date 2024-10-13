namespace CasDotnetSdk.Hybrid.Types
{
    public class HpkeEncryptResult
    {
        public byte[] EncappedKey { get; set; }
        public byte[] Ciphertext { get; set; }
        public byte[] Tag { get; set; }
    }
}
