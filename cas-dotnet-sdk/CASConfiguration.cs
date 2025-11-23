namespace CasDotnetSdk
{
    public static class CASConfiguration
    {
        static CASConfiguration()
        {
            IsDevelopment = false;
            Url = "https://cryptographicapiservices.com/";
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
                    return "https://localhost:8081";
                }
                else
                {
                    return _Url;
                }
            }
            set { _Url = value; }
        }
    }
}
