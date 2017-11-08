namespace AzureAD.Samples.OfflineAuthN.Authentication
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using Microsoft.IdentityModel.Tokens;

    /// <summary>
    /// In-memory token replay cache
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class TokenReplayCache : ITokenReplayCache
    {
        /// <summary>
        /// The key
        /// </summary>
        private const string Key = "IdTokenCache";

        /// <summary>
        /// cache Provider Object to store and validate token 
        /// </summary>
        private readonly ITokenCache cache;

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenReplayCache" /> class.
        /// </summary>
        /// <param name="cache">Interface reference for Cache Provider</param>
        public TokenReplayCache(ITokenCache cache)
        {
            this.cache = cache;
        }

        /// <summary>
        /// Try to add a securityToken
        /// </summary>
        /// <param name="securityToken">the security token to add.</param>
        /// <param name="expiresOn">the time when security token expires.</param>
        /// <returns>
        /// true if the security token was successfully added.
        /// </returns>
        public bool TryAdd(string securityToken, DateTime expiresOn)
        {
            var idTokens = this.cache.Get<List<string>>(Key);
            if (!idTokens.Contains(securityToken))
            {
                idTokens.Add(securityToken);
                this.cache.Set<List<string>>(Key, idTokens);
                return true;
            }

            return false;
        }

        /// <summary>
        /// Try to find securityToken
        /// </summary>
        /// <param name="securityToken">the security token to find.</param>
        /// <returns>
        /// true if the security token is found.
        /// </returns>
        public bool TryFind(string securityToken)
        {
            var idTokens = this.cache.Get<List<string>>(Key);
            if (null == idTokens)
            {
                idTokens = new List<string>();
                this.cache.Set<List<string>>(Key, idTokens);
                return false;
            }

            return idTokens.Contains(securityToken);
        }
    }
}