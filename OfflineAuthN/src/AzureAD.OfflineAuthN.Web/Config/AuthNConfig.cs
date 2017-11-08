namespace AzureAD.Samples.OfflineAuthN.Config
{
    /// <summary>
    /// Authentication Config holds configuration for Authentication Provider
    /// </summary>
    public class AuthNConfig
    {
        /// <summary>
        /// Gets or sets the azure ad.
        /// </summary>
        /// <value>
        /// The azure ad.
        /// </value>
        public AzureAdConfig AzureAD
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the authentication token store
        /// </summary>
        /// <value>
        /// Authentication token store.
        /// </value>
        public OfflineTokenStoreConfig AuthTokenStore
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the public key token store
        /// </summary>
        /// <value>
        /// public key token store.
        /// </value>
        public OfflineTokenStoreConfig PublicKeyTokenStore
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the Id token store
        /// </summary>
        /// <value>
        /// Id token store.
        /// </value>
        public OfflineTokenStoreConfig IdTokenStore
        {
            get;
            set;
        }
    }
}
