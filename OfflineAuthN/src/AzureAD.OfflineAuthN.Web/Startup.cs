namespace AzureAD.Samples.OfflineAuthN
{
    using System;
    using System.IO;
    using System.Threading.Tasks;
    using AzureAD.Samples.OfflineAuthN.Authentication;
    using AzureAD.Samples.OfflineAuthN.Caching;
    using AzureAD.Samples.OfflineAuthN.Config;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Authentication.OpenIdConnect;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc.Authorization;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Logging;
    using Microsoft.IdentityModel.Clients.ActiveDirectory;
    using Microsoft.IdentityModel.Protocols.OpenIdConnect;
    using Microsoft.IdentityModel.Tokens;

    /// <summary>
    /// The Startup Class
    /// </summary>
    public class Startup
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Startup"/> class.
        /// </summary>
        /// <param name="configuration">The configuration.</param>
        public Startup(IConfiguration configuration)
        {
            this.Configuration = configuration;

        }

        /// <summary>
        /// Gets the configuration.
        /// </summary>
        /// <value>
        /// The configuration.
        /// </value>
        public IConfiguration Configuration { get; }

        /// <summary>
        /// Gets the application settings.
        /// </summary>
        /// <value>
        /// The application settings.
        /// </value>
        public AppSettings AppSettings { get; private set; }

        /// <summary>
        /// Gets the logger.
        /// </summary>
        /// <value>
        /// The logger.
        /// </value>
        public ILogger Logger { get; private set; }

        /// <summary>
        /// Configures the services.
        /// </summary>
        /// <param name="services">The services.</param>
        /// <remarks>This method gets called by the runtime. Use this method to add services to the container.</remarks>
        public void ConfigureServices(IServiceCollection services)
        {
            this.Configuration.Bind(this.AppSettings = new AppSettings());
            services.AddSingleton<AppSettings>(this.AppSettings);
            services.AddSingleton<AuthNConfig>(this.AppSettings.AuthN);

            // Add Caching for Token Replay.
            ITokenCache tokenCache = new MemoryTokenCache();
            services.AddSingleton<ITokenCache>(tokenCache);
            services.AddAuthentication(sharedOptions =>
            {
                sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                sharedOptions.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(options =>
            {
                // In case you want offline authentication
                options.Cookie = new CookieBuilder
                {
                    HttpOnly = true,
                    SecurePolicy = CookieSecurePolicy.Always
                    //// SecurePolicy = this.AppSettings.HttpSecurity.IsSslEnabled ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest
                };
            }).AddOpenIdConnect(options =>
            {
                options.ClientId = this.AppSettings.AuthN.AzureAD.ClientId;
                options.Authority = this.AppSettings.AuthN.AzureAD.Authority;
                options.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.Events = new OpenIdConnectEvents
                {
                    OnAuthorizationCodeReceived = this.OnAuthorizationCodeReceived
                };
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    TokenReplayCache = new TokenReplayCache(tokenCache)
                };
            });

            services.AddMvc(options =>
            {
                // Add Authenticated Users only for allowing access to application.
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
                options.Filters.Add(new AuthorizeFilter(policy));
            });
        }

        /// <summary>
        /// Configures the specified application.
        /// </summary>
        /// <param name="app">The application.</param>
        /// <param name="env">The env.</param>
        /// <param name="serviceProvider">The service provider.</param>
        /// <param name="logger">The logger.</param>
        /// <remarks>
        /// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        /// </remarks>
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, IServiceProvider serviceProvider, ILogger logger)
        {
            this.Logger = logger;
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Error");
            }

            app.UseStaticFiles();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller}/{action=Index}/{id?}");
            });
        }

        /// <summary>
        /// The On Authorization Code Received Method
        /// </summary>
        /// <param name="context">Authorization Code Received Context</param>
        /// <returns>
        /// Returns async Task
        /// </returns>
        public async Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedContext context)
        {
            AuthenticationResult result = await this.GenerateTokenAsync(context, this.AppSettings.AuthN, this.AppSettings.AuthN.AzureAD.ResourceId, this.AppSettings.AuthN.AuthTokenStore.TokenFilePath);
            context.HandleCodeRedemption();
            string path = Environment.ExpandEnvironmentVariables(this.AppSettings.AuthN.PublicKeyTokenStore.TokenFilePath);
            string directoryPath = path.Split('.')[0];
            if (!Directory.Exists(directoryPath))
            {
                Directory.CreateDirectory(directoryPath.Substring(0, directoryPath.LastIndexOf('\\')));
            }

            path = Environment.ExpandEnvironmentVariables(this.AppSettings.AuthN.IdTokenStore.TokenFilePath);
            AzureTokenExtensions.SerializeIdToken(result.IdToken, path, this.Logger);
        }

        /// <summary>
        /// Generates the token.
        /// </summary>
        /// <param name="context">The notification.</param>
        /// <param name="authentication">The authentication.</param>
        /// <param name="resourceId">The resource identifier.</param>
        /// <param name="tokenPath">The token path.</param>
        /// <returns>
        /// return Authentication result
        /// </returns>
        private async Task<AuthenticationResult> GenerateTokenAsync(AuthorizationCodeReceivedContext context, AuthNConfig authentication, string resourceId, string tokenPath)
        {
            string userObjectId = context.Ticket.Principal.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;
            TokenCache cache;
            if (this.AppSettings.Hosting.OnDesktop)
            {
                string path = Environment.ExpandEnvironmentVariables(tokenPath);
                string directoryPath = path.Substring(0, path.LastIndexOf('\\'));
                if (!Directory.Exists(directoryPath))
                {
                    Directory.CreateDirectory(directoryPath);
                }

                cache = new FileBaseTokenCache(path);
            }
            else
            {
                cache = new TokenSessionCache(userObjectId, context.HttpContext.Session);
            }

            // Acquire a Token for the Resource and cache it.  
            ClientCredential clientCred = new ClientCredential(authentication.AzureAD.ClientId, authentication.AzureAD.ClientSecret);
            AuthenticationContext authContext = new AuthenticationContext(authentication.AzureAD.Authority, cache);
            AuthenticationResult authResult = await authContext.AcquireTokenByAuthorizationCodeAsync(context.ProtocolMessage.Code, new Uri(context.Properties.Items[OpenIdConnectDefaults.RedirectUriForCodePropertiesKey]), clientCred, resourceId);
            return authResult;
        }

        /// <summary>
        /// Redirects to login if no token exists
        /// </summary>
        /// <param name="context">The context.</param>
        private void RedirectToLogin(HttpContext context)
        {
            string authTokenPath = Environment.ExpandEnvironmentVariables(this.AppSettings.AuthN.AuthTokenStore.TokenFilePath);
            string idTokenPath = Environment.ExpandEnvironmentVariables(this.AppSettings.AuthN.IdTokenStore.TokenFilePath);
            if (!File.Exists(authTokenPath) || !File.Exists(idTokenPath))
            {
                if (context.Request.Path.Value != "/Account/login" && !context.Request.Path.Value.Equals("/account/AccessDenied", StringComparison.OrdinalIgnoreCase))
                {
                    context.Response.Clear();
                    context.Request.Path = "/Account/login";
                    context.Request.Method = "GET";
                }
            }
        }
    }
}
