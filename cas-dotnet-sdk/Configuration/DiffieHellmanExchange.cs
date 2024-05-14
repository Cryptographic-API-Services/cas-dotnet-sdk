using CasDotnetSdk.KeyExchange;
using CasDotnetSdk.KeyExchange.Types;
using CasDotnetSdk.Symmetric;
using CasDotnetSdk.Symmetric.Types;
using CASHelpers;
using CASHelpers.Types.HttpResponses.UserAuthentication;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
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
        public byte[] AesNonce { get; set; }
        private byte[] PublicKey { get; set; }
        private byte[] Secret { get; set; }
        private byte[] SharedSecret { get; set; }
        private X25519Wrapper _x25519Wrapper { get; set; }

        public DiffieHellmanExchange()
        {
            this._x25519Wrapper = new X25519Wrapper();
            X25519SecretPublicKey secretPublicKey = this._x25519Wrapper.GenerateSecretAndPublicKey();
            PublicKey = secretPublicKey.PublicKey;
            Secret = secretPublicKey.SecretKey;
        }

        public async Task CreateSharedSecretWithServer()
        {
            string macAddress = CASConfiguration.Networking.MacAddress;
            HttpClientSingleton httpClient = HttpClientSingleton.Instance;
            string url = CASConfiguration.Url + "/Authentication/DiffieHellmanAesKey";
            DiffieHellmanAesDerivationRequest request = new DiffieHellmanAesDerivationRequest()
            {
                MacAddress = macAddress,
                RequestersPublicKey = this.PublicKey
            };
            httpClient.DefaultRequestHeaders.Add(Constants.HeaderNames.Authorization, CASConfiguration.TokenCache.Token);
            HttpResponseMessage response = httpClient.PostAsJsonAsync(url, request).GetAwaiter().GetResult();
            while (!response.IsSuccessStatusCode)
            {
                response = await httpClient.PostAsJsonAsync(url, request);
            }
            string content = await response.Content.ReadAsStringAsync();
            JsonSerializerOptions options = new JsonSerializerOptions()
            {
                PropertyNameCaseInsensitive = true,
            };
            DiffieHellmanAesDerivationResponse parsedContent = JsonSerializer.Deserialize<DiffieHellmanAesDerivationResponse>(content, options);
            X25519SharedSecret sharedSecret = this._x25519Wrapper.GenerateSharedSecret(this.Secret, parsedContent.ResponsersPublicKey);
            this.SharedSecret = sharedSecret.SharedSecret;
            AESWrapper aes = new AESWrapper();
            Aes256KeyAndNonceX25519DiffieHellman aesKey = aes.Aes256KeyNonceX25519DiffieHellman(this.SharedSecret);
            this.AESKey = aesKey.AesKey;
            this.AesNonce = aesKey.AesNonce;
        }
    }
}
