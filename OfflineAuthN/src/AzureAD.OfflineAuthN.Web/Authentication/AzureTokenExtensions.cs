namespace AzureAD.Samples.OfflineAuthN.Authentication
{
    #region
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using AzureAD.Samples.OfflineAuthN.Config;
    using Microsoft.Extensions.Logging;
    using Microsoft.IdentityModel.Clients.ActiveDirectory;
    using Microsoft.IdentityModel.Protocols;
    using Microsoft.IdentityModel.Protocols.OpenIdConnect;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Bson;

    #endregion

    /// <summary>
    /// Azure Token Helper to retrieve token, Keys from azure and cache
    /// </summary>
    public static class AzureTokenExtensions
    {
        /// <summary>
        /// Deserializes the identifier token.
        /// </summary>
        /// <param name="path">The path.</param>
        /// <returns>id token</returns>
        public static string DeserializeIdToken(string path)
        {
            if (File.Exists(path))
            {
                try
                {
                    var arrBytes = ProtectedData.Unprotect(File.ReadAllBytes(path), null, DataProtectionScope.CurrentUser);
                    return Encoding.UTF8.GetString(arrBytes);
                }
                catch (CryptographicException)
                {
                    File.Delete(path);
                }
            }

            return string.Empty;
        }

        /// <summary>
        /// Gets the authentication token silently.
        /// </summary>
        /// <param name="authenticationConfig">The Authentication Configuration.</param>
        /// <returns>
        /// Authentication Token
        /// </returns>
        public static string GetAuthenticationTokenSilently(this AuthNConfig authenticationConfig, ILogger logger)
        {
            string path = Environment.ExpandEnvironmentVariables(authenticationConfig.AuthTokenStore.TokenFilePath);
            try
            {
                FileBaseTokenCache cache = new FileBaseTokenCache(path);
                var authContext = new AuthenticationContext(authenticationConfig.AzureAD.Authority, cache);
                return authContext.TokenCache.ReadItems().FirstOrDefault()?.AccessToken;
            }
            catch (CryptographicException ex)
            {
                logger.LogError(ex, "Error on getting authentication token silently.");
                if (File.Exists(path))
                {
                    File.Delete(path);
                }

                return string.Empty;
            }
        }

        /// <summary>
        /// Get Authentication Result From Cache or Azure Active Directory
        /// </summary>
        /// <param name="authenticationConfig"> authentication configuration.
        /// </param>
        /// <param name="cache"> Cache Object
        /// </param>
        /// <param name="userIdentifier"> User Identifier
        /// </param>
        /// <returns> Return Authentication result
        /// </returns>
        public static AuthenticationResult GetAuthenticationResult(this AuthNConfig authenticationConfig, TokenCache cache, UserIdentifier userIdentifier)
        {
            AuthenticationContext authContext;
            if (cache == null)
            {
                authContext = new AuthenticationContext(authenticationConfig.AzureAD.Authority);
            }
            else
            {
                authContext = new AuthenticationContext(authenticationConfig.AzureAD.Authority, cache);
            }

            ClientCredential credential = new ClientCredential(
                            authenticationConfig.AzureAD.ClientId,
                            authenticationConfig.AzureAD.ClientSecret);

            AuthenticationResult result = authContext.AcquireTokenSilentAsync(
                            authenticationConfig.AzureAD.ResourceId,
                            credential,
                            userIdentifier).Result;
            return result;
        }

        /// <summary>
        /// Get Authentication Result On-Behalf-Of for other Services
        /// </summary>
        /// <param name="authenticationConfig"> authentication configuration.
        /// </param>
        /// <param name="azureAd">The Azure Ad Config</param>
        /// <param name="claims">The user claims</param>
        /// <param name="token">The user token</param>
        /// <returns> Return Authentication result
        /// </returns>
        public static AuthenticationResult GetAuthenticationResultOnBehalfOf(this AuthNConfig authenticationConfig, AzureAdConfig azureAd, IEnumerable<Claim> claims, string token)
        {
            try
            {
                string userName = claims.FirstOrDefault(m => m.Type == "upn") != null ? claims.FirstOrDefault(m => m.Type == "upn")?.Value : claims.FirstOrDefault(m => m.Type == ClaimTypes.Email)?.Value;
                UserAssertion userAssertion = new UserAssertion(token, "urn:ietf:params:oauth:grant-type:jwt-bearer", userName);
                ClientCredential clientCredential = new ClientCredential(azureAd.ClientId, azureAd.ClientSecret);
                AuthenticationContext authContext = new AuthenticationContext(azureAd.Authority);
                return authContext.AcquireTokenAsync(authenticationConfig.AzureAD.ResourceId, clientCredential, userAssertion).Result;
            }
            catch (AggregateException ex)
            {
                if (ex.HasException<AdalException>() && ((AdalException)ex.InnerException).ErrorCode == "failed_to_acquire_token_silently")
                {
                    if (ex.HasExceptionStatus(System.Net.WebExceptionStatus.NameResolutionFailure)
                        || ex.HasExceptionStatus(System.Net.WebExceptionStatus.ConnectFailure)
                        || ex.HasExceptionStatus(System.Net.WebExceptionStatus.ConnectionClosed)
                        || ex.HasExceptionStatus(System.Net.WebExceptionStatus.Timeout)
                        || ex.HasExceptionStatus(System.Net.WebExceptionStatus.ProxyNameResolutionFailure)
                        || ex.HasExceptionStatus(System.Net.WebExceptionStatus.ReceiveFailure)
                        || ex.HasExceptionStatus(System.Net.WebExceptionStatus.KeepAliveFailure))
                    {
                        throw new Exception("AZ1001: Azure Active Directory connection not available, failed to retrieve token silently.");
                    }
                }

                throw;
            }
        }

        /// <summary>
        /// Gets the authentication result client credential.
        /// </summary>
        /// <param name="authenticationConfig"> authentication configuration.
        /// </param>
        /// <returns>Return Authentication result</returns>
        public static AuthenticationResult GetAuthenticationResultClientCredential(this AuthNConfig authenticationConfig)
        {
            ClientCredential clientCredential = new ClientCredential(authenticationConfig.AzureAD.ClientId, authenticationConfig.AzureAD.ClientSecret);
            AuthenticationContext authContext = new AuthenticationContext(authenticationConfig.AzureAD.Authority);
            Task<AuthenticationResult> resultTask = Task.Run(async () =>
           {
               return await authContext.AcquireTokenAsync(authenticationConfig.AzureAD.ResourceId, clientCredential).ConfigureAwait(true);
           });

            resultTask.Wait();
            return resultTask.Result;
        }

        /// <summary>
        /// Get authentication Token From Cache 
        /// </summary>
        /// <param name="authenticationConfig"> authentication configuration.
        /// </param>
        /// <param name="cache"> Cache Object
        /// </param>
        /// <returns> Return authentication Token
        /// </returns>
        public static string GetTokenFromCache(this AuthNConfig authenticationConfig, TokenCache cache)
        {
            AuthenticationContext authContext =
                   new AuthenticationContext(authenticationConfig.AzureAD.Authority, cache);
            return authContext.TokenCache.ReadItems().FirstOrDefault()?.AccessToken;
        }

        /// <summary>
        /// Refresh Authentication Token from File Based Token Cache
        /// </summary>
        /// <param name="authenticationConfig">authentication configuration.</param>
        /// <param name="resourceId">The resource identifier.</param>
        /// <param name="path">The path.</param>
        /// <returns>access token</returns>
        public static string RefreshAuthToken(this AuthNConfig authenticationConfig, string resourceId, string path, ILogger logger)
        {
            path = Environment.ExpandEnvironmentVariables(path);
            try
            {
                if (File.Exists(path))
                {
                    TokenCache cache = new FileBaseTokenCache(path);
                    ClientCredential credential = new ClientCredential(
                                    authenticationConfig.AzureAD.ClientId,
                                    authenticationConfig.AzureAD.ClientSecret);
                    AuthenticationContext authContext = new AuthenticationContext(authenticationConfig.AzureAD.Authority, cache);
                    AuthenticationResult result = authContext.AcquireTokenSilentAsync(
                                    resourceId,
                                    credential,
                                    UserIdentifier.AnyUser).Result;
                    return result.AccessToken;
                }
            }
            catch (AggregateException ex)
            {
                if (ex.InnerException is AdalException && ((AdalException)ex.InnerException).ErrorCode == "failed_to_acquire_token_silently")
                {
                    if (!ex.HasExceptionStatus(System.Net.WebExceptionStatus.NameResolutionFailure)
                        && !ex.HasExceptionStatus(System.Net.WebExceptionStatus.ConnectFailure)
                        && !ex.HasExceptionStatus(System.Net.WebExceptionStatus.ConnectionClosed)
                        && !ex.HasExceptionStatus(System.Net.WebExceptionStatus.Timeout)
                        && !ex.HasExceptionStatus(System.Net.WebExceptionStatus.ProxyNameResolutionFailure)
                        && !ex.HasExceptionStatus(System.Net.WebExceptionStatus.ReceiveFailure)
                        && !ex.HasExceptionStatus(System.Net.WebExceptionStatus.KeepAliveFailure))
                    {
                        File.Delete(path);
                    }
                }

                logger.LogError(ex, "Error on refresh auth token.");
            }
            catch (System.Exception ex)
            {
                logger.LogError(ex, "Error on refresh auth token.");
            }

            return string.Empty;
        }

        /// <summary>
        /// Refreshes the public key.
        /// </summary>
        /// <param name="authenticationConfig"> authentication configuration.
        /// </param>
        public static void RefreshAzurePublicKey(this AuthNConfig authenticationConfig, ILogger logger)
        {
            AzurePublicKeys azurePublicKey;
            string keyPath = Environment.ExpandEnvironmentVariables(authenticationConfig.PublicKeyTokenStore.TokenFilePath);
            azurePublicKey = DeserializeAzurePublicKey(keyPath);
            if (azurePublicKey != null && DateTime.UtcNow.Subtract(azurePublicKey.KeyRetrievalTime).TotalHours > 24)
            {
                azurePublicKey = authenticationConfig.GetAzurePublicKeyFromAzure();
                azurePublicKey.SerializeAzurePublicKey(keyPath, logger);
            }
        }

        /// <summary>
        /// Get Azure Public Keys for validation from Azure
        /// </summary>
        /// <param name="authenticationConfig"> authentication configuration.
        /// </param>
        /// <returns>
        /// Return Azure Public Keys
        /// </returns>
        public static AzurePublicKeys GetAzurePublicKeyFromAzure(this AuthNConfig authenticationConfig)
        {
            string authority = authenticationConfig.AzureAD.Authority;
            string stsDiscoveryEndpoint = $"{authority}/.well-known/openid-configuration";
            OpenIdConnectConfigurationRetriever retriever = new OpenIdConnectConfigurationRetriever();

            // Get tenant information that's used to validate incoming JWT tokens
            ConfigurationManager<OpenIdConnectConfiguration> configManager =
                new ConfigurationManager<OpenIdConnectConfiguration>(stsDiscoveryEndpoint, retriever);
            OpenIdConnectConfiguration config = configManager.GetConfigurationAsync().Result;

            AzurePublicKeys azurePublicKeys = new AzurePublicKeys
            {
                JsonWebKeySet = config.JsonWebKeySet,
                Issuer = config.Issuer,
                KeyRetrievalTime = DateTime.UtcNow
            };

            return azurePublicKeys;
        }

        /// <summary>
        /// Serialize Azure Public Key to File
        /// </summary>
        /// <param name="azurePublicKeys"> Azure Public Keys Object
        /// </param>
        /// <param name="path"> File Path where public keys will be saved
        /// </param>
        public static void SerializeAzurePublicKey(this AzurePublicKeys azurePublicKeys, string path, ILogger logger)
        {
            try
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    using (BsonDataWriter bsonDataWriter = new BsonDataWriter(ms))
                    {
                        JsonSerializerSettings jsonSerializerSetting = new JsonSerializerSettings();
                        jsonSerializerSetting.TypeNameHandling = TypeNameHandling.All;
                        jsonSerializerSetting.Formatting = Formatting.None;
                        var serializer = JsonSerializer.CreateDefault(jsonSerializerSetting);
                        serializer.Serialize(bsonDataWriter, azurePublicKeys);
                        bsonDataWriter.Flush();
                        ms.Seek(0, SeekOrigin.Begin);
                        File.WriteAllBytes(path, ProtectedData.Protect(ms.ToArray(), null, DataProtectionScope.CurrentUser));
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error on serializing azure public key.", ex);
            }
        }

        /// <summary>
        /// Deserialize Azure Public Key from File to AzurePublicKeys Object
        /// </summary>
        /// <param name="path"> File Path from where public keys will be retrieved
        /// </param>
        /// <returns> Returns AzurePublicKeys
        /// </returns>
        public static AzurePublicKeys DeserializeAzurePublicKey(string path)
        {
            if (File.Exists(path))
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    JsonSerializerSettings jsonSerializerSetting = new JsonSerializerSettings();
                    jsonSerializerSetting.TypeNameHandling = TypeNameHandling.All;
                    jsonSerializerSetting.Formatting = Formatting.None;
                    var serializer = JsonSerializer.CreateDefault(jsonSerializerSetting);
                    var arrBytes = ProtectedData.Unprotect(File.ReadAllBytes(path), null, DataProtectionScope.CurrentUser);
                    ms.Write(arrBytes, 0, arrBytes.Length);
                    ms.Seek(0, SeekOrigin.Begin);
                    using (BsonDataReader bsonDataReader = new BsonDataReader(ms))
                    {
                        return serializer.Deserialize<AzurePublicKeys>(bsonDataReader);
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Serializes the identifier token.
        /// </summary>
        /// <param name="idToken">The identifier token.</param>
        /// <param name="path">The path.</param>
        public static void SerializeIdToken(string idToken, string path, ILogger logger)
        {
            try
            {
                File.WriteAllBytes(path, ProtectedData.Protect(Encoding.UTF8.GetBytes(idToken), null, DataProtectionScope.CurrentUser));
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error on serializing azure ID Token.");
            }
        }

        /// <summary>
        /// Gets the daemon token.
        /// </summary>
        /// <param name="authenticationConfig"> authentication configuration.
        /// </param>
        /// <returns>Authentication Result</returns>
        public static AuthenticationResult GetDaemonToken(this AuthNConfig authenticationConfig, ILogger logger)
        {
            try
            {
                AuthenticationContext authContext = new AuthenticationContext(authenticationConfig.AzureAD.Authority);
                ClientCredential clientCredential = new ClientCredential(authenticationConfig.AzureAD.ClientId, authenticationConfig.AzureAD.ClientSecret);
                AuthenticationResult authResult = authContext.AcquireTokenAsync(authenticationConfig.AzureAD.ResourceId, clientCredential).Result;
                return authResult;
            }
            catch (AdalException ex)
            {
                logger.LogError(ex, "Error on retrieving daemon token.");
                return null;
            }
            catch (AggregateException ex)
            {
                logger.LogError(ex, "Error on retrieving daemon token.");
                return null;
            }
        }

        /// <summary>
        /// Determines whether this instance has exception.
        /// </summary>
        /// <typeparam name="T">type of exception</typeparam>
        /// <param name="exception">The exception.</param>
        /// <returns>
        ///   <c>true</c> if the specified exception has exception; otherwise, <c>false</c>.
        /// </returns>
        public static bool HasException<T>(this Exception exception)
        {
            while (null != exception)
            {
                if (exception is T)
                {
                    return true;
                }

                exception = exception.InnerException;
            }

            return false;
        }

        /// <summary>
        /// Determines whether [has exception status] [the specified exception].
        /// </summary>
        /// <param name="exception">The exception.</param>
        /// <param name="status">The status.</param>
        /// <returns>
        ///   <c>true</c> if [has exception status] [the specified exception]; otherwise, <c>false</c>.
        /// </returns>
        public static bool HasExceptionStatus(this Exception exception, WebExceptionStatus status)
        {
            while (null != exception)
            {
                if (exception is WebException && ((WebException)exception).Status == status)
                {
                    return true;
                }

                exception = exception.InnerException;
            }

            return false;
        }
    }
}
