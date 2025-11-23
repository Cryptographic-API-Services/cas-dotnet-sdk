namespace CasDotnetSdk
{
    public static class CASConfiguration
    {
        static CASConfiguration()
        {
            IsDevelopment = false;
            IsStaging = false;
            Url = "https://cryptographicapiservices.com";
        }

        private static string _ApiKey;

        /// <summary>
        /// This is the property where you set your CAS User account API key from the CAS Dashboard.
        /// </summary>
        public static string ApiKey
        {
            get { return _ApiKey; }
            set
            {
                _ApiKey = value;
                // TODO: Update underlying Rust services with new API key
                // TODO: Get Token and RefreshToken from CAS services and store them securely in a Rust cache.
            }
        }

        private static bool _IsDevelopment;

        /// <summary>
        /// This method is mostly for development purposes of the SDk. We don't recommend changing this in a production environment.
        /// </summary>
        public static bool IsDevelopment
        {
            get { return _IsDevelopment; }
            set { 
                _IsDevelopment = value;
                // TODO: Update underlying Rust services to point to development environment
            }
        }

        /// <summary>
        /// This method is mostly for development purposes of the SDk. We don't recommend changing this in a production environment.
        /// </summary>
        private static bool _IsStaging;

        public static bool IsStaging
        {
            get { return _IsStaging; }
            set { 
                _IsStaging = value;
                // TODO: Update underlying Rust services to point to staging environment
            }
        }

        private static string _Url;
        internal static string Url
        {
            get
            {
                if (_IsDevelopment)
                {
                    return "http://localhost:5000";
                }
                else if (_IsStaging)
                {
                    return "https://staging.cryptographicapiservices.com";
                }
                else
                {
                    return "https://cryptographicapiservices.com";
                }
            }
            set { _Url = value; }
        }
    }
}
