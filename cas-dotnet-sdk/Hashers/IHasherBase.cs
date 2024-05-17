namespace CasDotnetSdk.Hashers
{
    public interface IHasherBase
    {
        public byte[] Hash512(byte[] dataToHash);
        public byte[] Hash512Threadpool(byte[] dataToHash);
        public bool Verify512(byte[] dataToVerify, byte[] hashedData);
        public bool Verify512Threadpool(byte[] dataToVerify, byte[] hashedData);
        public byte[] Hash256(byte[] dataToHash);
        public byte[] Hash256Threadpool(byte[] dataToHash);
        public bool Verify256(byte[] dataToVerify, byte[] hashedData);
        public bool Verify256Threadpool(byte[] dataToVerify, byte[] hashedData);
    }
}
