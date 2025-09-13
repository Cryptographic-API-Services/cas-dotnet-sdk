namespace CasDotnetSdk.PasswordHashers
{
    public interface IPasswordHasherBase
    {
        public string HashPassword(string password);
        public bool Verify(string hashedPassword, string verifyPassword);
    }
}
