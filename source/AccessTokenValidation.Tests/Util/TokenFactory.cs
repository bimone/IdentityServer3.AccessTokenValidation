using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace AccessTokenValidation.Tests.Util
{
    internal static class TokenFactory
    {
        public const string DefaultIssuer = "https://issuer";
        public const string DefaultAudience = "https://issuer/resources";
        public const string DefaultPublicKey = "MIIDGzCCAgOgAwIBAgIQH5CpsdJDH5ZJ89cWwFrMQDANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDDAppZHNydjN0ZXN0MB4XDTIxMTExNzIyMjUwOVoXDTQxMTExNzIyMzUxMFowFTETMBEGA1UEAwwKaWRzcnYzdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOprPYDL9KJ2WxNjUQKzyEgI/BOHeoz9z/2IflLiK4VCVDYYLrd35tB1X1bbBxQ77M9cgA6eqS5w8uHlITMz5wNQE8NB8nOBBD6Z3uOUSYcwd7oi639wV4M9BJRhufGUFCEN1dzRfqhpDBRklYEx5RKGEbaeQHwwuMRmuzx8QQagUJ3DCclIx9OKyOzc1ipjDL1j0WI1Q61BfptelnKULaZQrLa6b1YCTgMrPyuL9pT1qDrRvNAX/uykmzN/Jt/ms4gQlqyIYcy8398QtS7XSGmuWYdoD87bOG5iBkvPqRgbA/9PbYOePujYXo0ljfm+oRdTmA1qGpAVkOsNduDOgx0CAwEAAaNnMGUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAVBgNVHREEDjAMggppZHNydjN0ZXN0MB0GA1UdDgQWBBRqyXCUtb/Ou1Ml8gBChx4/NA2LGDANBgkqhkiG9w0BAQsFAAOCAQEAYZ3qLITEIe72vccldlsze6JM0YqvdezAigmUzNMrptQu38Jq+152Z1d23nfhvhoQN69aJaIHVSt//N1Yrnjh/hKqiuYRzSS4/7S7aWWN1RLv1DawEySZeqkfsYpJLc2oqQSlkqb/8dijRXopppS2tUYWxfgEf0FT278KK1e4Pt/iVJzBhhtI0ngqWUeR+KonLoSL+nv7cO9DZPWFfQRrcDlDcR5cmEC9g4paRP3kYT524nhMKsMeD7E8ooup3vrlG4+S3QFdZyf90cJKm46rLt0rBnc/L0uncay2wnX83N4TlaxUFMjgHSHLFw1tal7tF1DWEovG9RDO6Gbk65qpPw==";

        public const string Api1Scope = "api1";
        public const string Api2Scope = "api2";

        private static X509Certificate2 signingCert;

        public static X509Certificate2 DefaultSigningCertificate
        {
            get
            {
                if (signingCert == null)
                {
                    signingCert = Cert.Load();
                }

                return signingCert;
            }
        }

        public static JwtSecurityToken CreateToken(
            string issuer = null,
            string audience = null,
            IEnumerable<string> scope = null,
            int ttl = 360,
            List<Claim> additionalClaims = null,
            X509Certificate2 signingCertificate = null)
        {
            if (additionalClaims == null)
            {
                additionalClaims = new List<Claim>();
            }

            scope?.ToList().ForEach(s => additionalClaims.Add(new Claim("scope", s)));
            
            var signingKey = new SigningCredentials(new X509SecurityKey(DefaultSigningCertificate), SecurityAlgorithms.RsaSha256Signature);
            var token = new JwtSecurityToken(
                issuer ?? DefaultIssuer,
                audience ?? DefaultAudience,
                additionalClaims,
                DateTime.UtcNow,
                DateTime.UtcNow.AddSeconds(ttl),
                signingKey);

            return token;
        }

        public static string CreateTokenString(JwtSecurityToken token)
        {
            JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap = new Dictionary<string, string>();

            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(token);
        }
    }
}
