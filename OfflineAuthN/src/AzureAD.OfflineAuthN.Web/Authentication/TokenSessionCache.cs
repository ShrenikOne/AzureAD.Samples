namespace AzureAD.Samples.OfflineAuthN.Authentication
{
    #region

    using System.Diagnostics.CodeAnalysis;
    using Microsoft.AspNetCore.Http;
    using Microsoft.IdentityModel.Clients.ActiveDirectory;

    #endregion

    /// <summary>
    /// This is a simple persistent Session cache implementation. It stored the token in Session.
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class TokenSessionCache : TokenCache
    {
        #region Implementation of TokenSessionCache

        /// <summary>
        /// lock object for thread safe
        /// </summary>
        private static readonly object FileLock = new object();

        /// <summary>
        /// Reference Object for Session
        /// </summary>
        private readonly ISession session = null;

        /// <summary>
        /// User Object Id
        /// </summary>
        private string userObjectId;

        /// <summary>
        /// The cache Id
        /// </summary>
        private string cacheId;

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenSessionCache" /> class.
        /// </summary>
        /// <param name="userId">
        /// The user identifier.
        /// </param>
        /// <param name="session">
        /// The session.
        /// </param>
        public TokenSessionCache(string userId, ISession session)
        {
            this.userObjectId = userId;
            this.cacheId = this.userObjectId + "_TokenCache";
            this.session = session;
            this.AfterAccess = this.AfterAccessNotification;
            this.BeforeAccess = this.BeforeAccessNotification;
            this.Load();
        }

        /// <summary>
        /// Load the cache.
        /// </summary>
        public void Load()
        {
            lock (FileLock)
            {
                this.Deserialize((byte[])this.session.Get(this.cacheId));
            }
        }

        /// <summary>
        /// Persist the cache in session
        /// </summary>
        public void Persist()
        {
            lock (FileLock)
            {
                // reflect changes in the persistent store
                this.session.Set(this.cacheId, this.Serialize());

                // once the write operation took place, restore the HasStateChanged bit to false
                this.HasStateChanged = false;
            }
        }

        /// <summary>
        /// Empties the persistent store.
        /// </summary>
        public override void Clear()
        {
            base.Clear();
            this.session.Remove(this.cacheId);
        }

        /// <summary>
        /// Delete Cached Item from cache.
        /// </summary>
        /// <param name="item">
        /// The TokenCacheItem
        /// </param>
        public override void DeleteItem(TokenCacheItem item)
        {
            base.DeleteItem(item);
            this.Persist();
        }

        /// <summary>
        /// Triggered right before ADAL needs to access the cache. Reload the cache from the
        /// persistent store in case it changed since the last access.
        /// </summary>
        /// <param name="args">
        /// The TokenCacheNotificationArgs
        /// </param>
        private void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            this.Load();
        }

        /// <summary>
        /// Triggered right after ADAL accessed the cache.
        /// </summary>
        /// <param name="args">
        /// The TokenCacheNotificationArgs
        /// </param>
        private void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // if the access operation resulted in a cache update
            if (this.HasStateChanged)
            {
                this.Persist();
            }
        }

        #endregion
    }
}