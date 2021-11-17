﻿using System;
using AccessTokenValidation.Tests.Util;
using FluentAssertions;
using IdentityServer3.AccessTokenValidation;
using System.Net;
using System.Threading.Tasks;
using IdentityModel.Client;
using Xunit;

namespace AccessTokenValidation.Tests.Integration_Tests
{
    public class DynamicLocal
    {
        IdentityServerBearerTokenAuthenticationOptions _options = new IdentityServerBearerTokenAuthenticationOptions
        {
            Authority = "https://discodoc",
            ValidationMode = ValidationMode.Local,
            DelayLoadMetadata = true
        };

        [Fact]
        public async Task WhenDelayLoadMetadataIsTrue_MetadataRetrievalIsRetriedAfterFailure()
        {
            _options.BackchannelHttpHandler = new FailureDiscoveryEndpointHandler();

            var client = PipelineFactory.CreateHttpClient(_options);
            var token = TokenFactory.CreateTokenString(TokenFactory.CreateToken());

            client.SetBearerToken(token);

            Func<Task> action = async () => await client.GetAsync("http://test");

            Assert.ThrowsAsync<InvalidOperationException>(action)
                .Result.Message.Should().Contain("IDX20803"); // IDX20803: Unable to create to obtain configuration from: https://discodoc
            _options.BackchannelHttpHandler = new DiscoveryEndpointHandler();

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);
        }
    }
}