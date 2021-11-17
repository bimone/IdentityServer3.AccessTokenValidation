/*
 * Copyright 2015 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Jwt;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer3.AccessTokenValidation
{
    internal class DiscoveryDocumentIssuerSecurityTokenProvider : IIssuerSecurityKeyProvider
    {
        private readonly ReaderWriterLockSlim _synclock = new ReaderWriterLockSlim();
        private readonly ConfigurationManager<OpenIdConnectConfiguration> _configurationManager;
        private readonly ILogger _logger;
        private string _issuer;
        private ICollection<SecurityKey> _keys;

        public DiscoveryDocumentIssuerSecurityTokenProvider(string discoveryEndpoint, IdentityServerBearerTokenAuthenticationOptions options, ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.Create(this.GetType().FullName);

            var handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException("The back channel handler must derive from WebRequestHandler in order to use a certificate validator");
                }
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            _configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(discoveryEndpoint, new OpenIdConnectConfigurationRetriever(), new HttpClient(handler))
            {
                AutomaticRefreshInterval = options.AutomaticRefreshInterval
            };

            if (!options.DelayLoadMetadata)
            {
                RetrieveMetadata();
            }
        }

        /// <summary>
        /// Gets the issuer the credentials are for.
        /// </summary>
        /// <value>
        /// The issuer the credentials are for.
        /// </value>
        public string Issuer
        {
            get
            {
                RetrieveMetadata();
                _synclock.EnterReadLock();
                try
                {
                    return _issuer;
                }
                finally
                {
                    _synclock.ExitReadLock();
                }
            }
        }

        /// <value>
        /// The identity server default audience
        /// </value>
        public string Audience
        {
            get
            {
                RetrieveMetadata();
                _synclock.EnterReadLock();
                try
                {
                    string issuer = _issuer.EnsureTrailingSlash();
                    return issuer + "resources";
                }
                finally
                {
                    _synclock.ExitReadLock();
                }
            }
        }

        public IEnumerable<Microsoft.IdentityModel.Tokens.SecurityKey> SecurityKeys
        {
            get
            {
                RetrieveMetadata();
                _synclock.EnterReadLock();
                try
                {
                    return _keys;
                }
                finally
                {
                    _synclock.ExitReadLock();
                }
            }
        }

        private void RetrieveMetadata()
        {
            _synclock.EnterWriteLock();
            try
            {
                OpenIdConnectConfiguration result = AsyncHelper.RunSync(async () => await _configurationManager.GetConfigurationAsync());

                if (result.JsonWebKeySet == null)
                {
                    _logger.WriteError("Discovery document has no configured signing key. aborting.");
                    throw new InvalidOperationException("Discovery document has no configured signing key. aborting.");
                }

                _issuer = result.Issuer;
                _keys = result.SigningKeys;
            }
            catch (Exception ex)
            {
                _logger.WriteError("Error contacting discovery endpoint: " + ex.ToString());
                throw;
            }
            finally
            {
                _synclock.ExitWriteLock();
            }
        }
    }
}