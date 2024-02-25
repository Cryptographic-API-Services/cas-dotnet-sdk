using CasDotnetSdk.KeyExchange;
using CasDotnetSdk.KeyExchange.Types;
using System.Threading.Tasks;

namespace CasDotnetSdk.Configuration
{
    /// <summary>
    /// Class used to communicate with the CAS server's to generate a Diffie Hellman Key utilizing the same Key Exchange utilized in 
    /// the KeyExchange folder and deriving an AES-256 key for encryption and decryption.
    /// </summary>
    internal class DiffieHellmanExchange
    {
        public string AESKey { get; set; }
        public string AesNonce { get; set; }
        private byte[] PublicKey { get; set; }
        private byte[] Secret { get; set; }
        private string SharedSecret { get; set; }
        private X25519Wrapper _x25519Wrapper { get; set; }

        public DiffieHellmanExchange()
        {
            this._x25519Wrapper = new X25519Wrapper();
            X25519SecretPublicKey secretPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            PublicKey = secretPublicKey.PublicKey;
            Secret = secretPublicKey.SecretKey;
        }

        public async Task CreateSharedSecretWithServers()
        {
            string macAddress = CASConfiguration.Networking.MacAddress;
        }
    }
}
