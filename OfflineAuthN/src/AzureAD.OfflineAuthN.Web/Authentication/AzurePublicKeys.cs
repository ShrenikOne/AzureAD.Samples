namespace AzureAD.Samples.OfflineAuthN.Authentication
{
    #region
    using System;
    using Microsoft.IdentityModel.Tokens;

    #endregion

    /// <summary>
    /// Serializable Azure Public Keys
    /// </summary>
    public class AzurePublicKeys
    {
        /// <summary>
        /// Gets or sets serializable object Web Key Set
        /// </summary>
        public JsonWebKeySet JsonWebKeySet
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the Key Issuer
        /// </summary>>
        public string Issuer
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the key retrieval time.
        /// </summary>
        /// <value>
        /// The key retrieval time.
        /// </value>
        public DateTime KeyRetrievalTime
        {
            get;
            set;
        }
    }
}
