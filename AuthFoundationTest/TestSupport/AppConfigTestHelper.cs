using AuthFoundation.Common;
using Microsoft.Extensions.Configuration;

namespace AuthFoundationTest.TestSupport;

internal static class AppConfigTestHelper
{
    public static void Initialize(IReadOnlyDictionary<string, string?>? overrides = null)
    {
        var values = new Dictionary<string, string?>
        {
            ["PasswordHashKey"] = "AuthFoundation_Test_PasswordHashKey_0123456789abcdef",
            ["JwkPrivateKeyEncryptionKey"] = "AuthFoundation_Test_JwkEncryptionKey_0123456789abcdef",
            ["Session_ExpireSec"] = "900",
            ["AccessToken_ExpireSec"] = "900",
            ["RefreshToken_ExpireSec"] = "7776000",
            ["IDToken_ExpireSec"] = "3600",
            ["JwkSigningKeyReloadSec"] = "300",
            ["RedisDb_Default"] = "0",
            ["RedisDb_LoginSession"] = "1",
            ["RedisDb_AuthCode"] = "2",
            ["RedisDb_AccessToken"] = "3",
            ["RedisDb_RefreshToken"] = "4",
            ["RedisDb_AuthRequestSession"] = "6",
            ["RedisDb_SignupSession"] = "7",
            ["RedisDb_IdTokenRevocation"] = "8",
            ["RedisDb_LogoutAllRevocation"] = "9"
        };

        if (overrides is not null)
        {
            foreach ((string key, string? value) in overrides)
            {
                values[key] = value;
            }
        }

        IConfiguration config = new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();

        AppConfig.Initialize(config);
    }
}

