namespace CasDotnetSdk.Hashers
{
    public interface IHasherBase
    {
        public byte[] Hash512(byte[] dataToHash);
        public bool Verify512(byte[] dataToVerify, byte[] hashedData);
        public byte[] Hash256(byte[] dataToHash);
        public bool Verify256(byte[] dataToVerify, byte[] hashedData);
    }
}
