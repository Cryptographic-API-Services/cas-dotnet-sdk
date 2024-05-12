namespace CasDotnetSdk.PasswordHashers
{
    public interface IPasswordHasherBase
    {
        public string HashPassword(string password);
        public bool Verify(string hashedPassword, string verifyPassword);
        public string HashPasswordThreadPool(string password);
        public bool VerifyThreadPool(string hashedPassword, string verifyPassword);
    }
}
