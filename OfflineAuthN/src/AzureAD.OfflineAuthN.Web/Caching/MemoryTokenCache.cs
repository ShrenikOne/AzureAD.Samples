namespace AzureAD.Samples.OfflineAuthN.Caching
{
    using System;
    using AzureAD.Samples.OfflineAuthN.Authentication;
    using Microsoft.Extensions.Caching.Memory;

    /// <summary>
    /// The Token Cache implements to cache token.
    /// </summary>
    /// <seealso cref="AzureAD.Samples.OfflineAuthN.Authentication.ITokenCache" />
    public class MemoryTokenCache : ITokenCache
    {
        /// <summary>
        /// The memory cache
        /// </summary>
        private readonly MemoryCache memoryCache;

        /// <summary>
        /// Initializes a new instance of the <see cref="MemoryTokenCache"/> class.
        /// </summary>
        public MemoryTokenCache()
        {
            this.memoryCache = new MemoryCache(new MemoryCacheOptions
            {
                ExpirationScanFrequency = TimeSpan.FromSeconds(30)
            });
        }

        /// <summary>
        /// Gets the specified key.
        /// </summary>
        /// <typeparam name="T">Type of object in cache</typeparam>
        /// <param name="key">The key.</param>
        /// <returns>
        /// Returns a cached object.
        /// </returns>
        public T Get<T>(string key)
        {
            return this.memoryCache.Get<T>(key);
        }

        /// <summary>
        /// Sets the specified key.
        /// </summary>
        /// <typeparam name="T">Type of object to cache</typeparam>
        /// <param name="key">The key.</param>
        /// <param name="value">The value.</param>
        public void Set<T>(string key, T value)
        {
            this.memoryCache.Set<T>(key, value);
        }
    }
}
