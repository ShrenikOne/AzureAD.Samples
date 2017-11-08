namespace AzureAD.Samples.OfflineAuthN.Authentication
{
    using System.IO;
    using System.Security.Cryptography;
    using System.Threading;
    using Microsoft.IdentityModel.Clients.ActiveDirectory;

    /// <summary>
    /// This is a simple persistent cache implementation. It uses DPAPI for storing tokens in a local file.
    /// </summary>
    public class FileBaseTokenCache : TokenCache
    {
        #region Implementation of FileCache

        /// <summary>
        /// The maximum retry count
        /// </summary>
        private const int MaxRetryCount = 3;

        /// <summary>
        /// lock object for thread safe
        /// </summary>
        private static readonly object FileLock = new object();

        /// <summary>
        /// Gets or sets Cache File Path
        /// </summary>
        private string cacheFilePath;

        /// <summary>
        /// The retry count
        /// </summary>
        private int retryCount;

        /// <summary>
        /// Initializes a new instance of the <see cref="FileBaseTokenCache" /> class.
        /// If the file is already present, it loads its content in the ADAL cache <see cref="FileBaseTokenCache"/>
        /// </summary>
        /// <param name="filePath">The File Path.
        /// </param>
        public FileBaseTokenCache(string filePath = @".\TokenCache.dat")
        {
            this.cacheFilePath = filePath;
            this.AfterAccess = this.AfterAccessNotification;
            this.BeforeAccess = this.BeforeAccessNotification;
            lock (FileLock)
            {
                this.ReadTokenFile();
            }
        }

        /// <summary>
        /// Empties the persistent store.
        /// </summary>
        public override void Clear()
        {
            base.Clear();
            if (File.Exists(this.cacheFilePath))
            {
                this.retryCount = 0;
                lock (FileLock)
                {
                    while (this.retryCount != MaxRetryCount)
                    {
                        try
                        {
                            File.Delete(this.cacheFilePath);
                            this.retryCount = MaxRetryCount;
                        }
                        catch (IOException)
                        {
                            this.retryCount++;
                            if (this.retryCount == MaxRetryCount)
                            {
                                throw;
                            }

                            Thread.Sleep(100);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Triggered right before ADAL needs to access the cache.
        /// Reload the cache from the persistent store in case it changed since the last access.
        /// </summary>
        /// <param name="args">The TokenCacheNotificationArgs
        /// </param>
        public void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            lock (FileLock)
            {
                this.ReadTokenFile();
            }
        }

        /// <summary>
        /// Triggered right after ADAL accessed the cache.
        /// </summary>
        /// <param name="args">The TokenCacheNotificationArgs
        /// </param>
        public void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // if the access operation resulted in a cache update
            if (this.HasStateChanged)
            {
                this.retryCount = 0;
                lock (FileLock)
                {
                    while (this.retryCount != MaxRetryCount)
                    {
                        try
                        {
                            // reflect changes in the persistent store
                            using (var stream = new FileStream(this.cacheFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                            {
                                var arr = ProtectedData.Protect(this.Serialize(), null, System.Security.Cryptography.DataProtectionScope.CurrentUser);
                                stream.Write(arr, 0, arr.Length);
                            }

                            this.retryCount = MaxRetryCount;
                        }
                        catch (IOException)
                        {
                            this.retryCount++;
                            if (this.retryCount == MaxRetryCount)
                            {
                                throw;
                            }

                            Thread.Sleep(100);
                        }
                    }

                    // once the write operation took place, restore the HasStateChanged bit to false
                    this.HasStateChanged = false;
                }
            }
        }

        /// <summary>
        /// Reads the token file.
        /// </summary>
        private void ReadTokenFile()
        {
            if (File.Exists(this.cacheFilePath))
            {
                this.retryCount = 0;
                while (this.retryCount != MaxRetryCount)
                {
                    try
                    {
                        using (var stream = new FileStream(this.cacheFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            byte[] bytes = new byte[stream.Length];
                            int numBytesToRead = (int)stream.Length;
                            int numBytesRead = 0;
                            while (numBytesToRead > 0)
                            {
                                int n = stream.Read(bytes, numBytesRead, numBytesToRead);
                                if (n == 0)
                                {
                                    break;
                                }

                                numBytesRead += n;
                                numBytesToRead -= n;
                            }

                            this.Deserialize(ProtectedData.Unprotect(bytes, null, DataProtectionScope.CurrentUser));
                        }

                        this.retryCount = MaxRetryCount;
                    }
                    catch (IOException)
                    {
                        this.retryCount++;
                        if (this.retryCount == MaxRetryCount)
                        {
                            throw;
                        }

                        Thread.Sleep(100);
                    }
                }
            }
        }
        #endregion
    }
}
