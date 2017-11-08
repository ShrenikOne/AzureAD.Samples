namespace AzureAD.Samples.OfflineAuthN.Config
{
    /// <summary>
    /// The AppSettings POCO to represent appsettings.*.json file.
    /// </summary>
    public class AppSettings
    {
        /// <summary>
        /// Gets or sets the authentication section.
        /// </summary>
        /// <value>
        /// The authentication section.
        /// </value>
        public AuthNConfig AuthN { get; set; }
    }
}
