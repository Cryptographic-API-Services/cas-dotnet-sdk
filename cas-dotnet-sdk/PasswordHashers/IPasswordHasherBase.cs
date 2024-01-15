namespace CasDotnetSdk.PasswordHashers
{
    public interface IPasswordHasherBase
    {
        public string HashPassword(string password);
        public bool VerifyPassword(string hashedPassword, string verifyPassword);
        string[] HashPasswordsThread(string[] passwordsToHash);
        public bool VerifyPasswordThread(string hashedPasswrod, string password);
    }
}
