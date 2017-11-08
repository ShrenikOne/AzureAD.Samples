namespace AzureAD.Samples.OfflineAuthN.Authentication
{
    /// <summary>
    /// The ITokenCache provide abstraction to hook-up any application level caching provider. i.e. Memory, Radis etc...
    /// </summary>
    public interface ITokenCache
    {
        /// <summary>
        /// Gets the specified key.
        /// </summary>
        /// <typeparam name="T">Type of object in cache</typeparam>
        /// <param name="key">The key.</param>
        /// <returns>Returns a cached object.</returns>
        T Get<T>(string key);

        /// <summary>
        /// Sets the specified key.
        /// </summary>
        /// <typeparam name="T">Type of object to cache</typeparam>
        /// <param name="key">The key.</param>
        /// <param name="value">The value.</param>
        void Set<T>(string key, T value);
    }
}