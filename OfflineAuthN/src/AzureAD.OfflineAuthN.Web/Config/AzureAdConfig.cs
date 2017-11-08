namespace AzureAD.Samples.OfflineAuthN.Config
{
    /// <summary>
    /// The Azure Active Directory Configuration
    /// </summary>
    public class AzureAdConfig
    {
        /// <summary>
        /// Gets or sets the add instance.
        /// </summary>
        /// <value>
        /// The add instance.
        /// </value>
        public string Instance { get; set; }

        /// <summary>
        /// Gets or sets the domain.
        /// </summary>
        /// <value>
        /// The domain.
        /// </value>
        public string Domain { get; set; }

        /// <summary>
        /// Gets or sets the tenant identifier.
        /// </summary>
        /// <value>
        /// The tenant identifier.
        /// </value>
        public string TenantId { get; set; }

        /// <summary>
        /// Gets or sets the client identifier.
        /// </summary>
        /// <value>
        /// The client identifier.
        /// </value>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the client secret.
        /// </summary>
        /// <value>
        /// The client secret.
        /// </value>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets the post log out redirect URI.
        /// </summary>
        /// <value>
        /// The post log out redirect URI.
        /// </value>
        public string PostLogoutRedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the Resource Id.
        /// </summary>
        /// <value>
        /// Resource Id.
        /// </value>
        public string ResourceId { get; set; }

        /// <summary>
        /// Gets the authority.
        /// </summary>
        /// <value>
        /// The authority.
        /// </value>
        public string Authority
        {
            get
            {
                return this.Instance + this.TenantId;
            }
        }
    }
}
