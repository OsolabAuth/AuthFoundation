using AuthFoundation.Common;
using Microsoft.Extensions.Configuration;

namespace AuthFoundationTest.TestSupport;

internal static class AppConfigTestHelper
{
    public static void Initialize()
    {
        var values = new Dictionary<string, string?>
        {
            ["PasswordHashKey"] = "AuthFoundation_Test_PasswordHashKey_0123456789abcdef",
            ["JwkPrivateKeyEncryptionKey"] = "AuthFoundation_Test_JwkEncryptionKey_0123456789abcdef",
            ["Session_ExpireSec"] = "900",
            ["AccessToken_ExpireSec"] = "900",
            ["RefreshToken_ExpireSec"] = "7776000",
            ["IDToken_ExpireSec"] = "3600",
            ["RedisDb_Default"] = "0",
            ["RedisDb_LoginSession"] = "1",
            ["RedisDb_AuthCode"] = "2",
            ["RedisDb_AccessToken"] = "3",
            ["RedisDb_RefreshToken"] = "4",
            ["RedisDb_AuthorizationSession"] = "6",
            ["RedisDb_MailVerification"] = "7",
            ["RedisDb_IdTokenRevocation"] = "8",
            ["RedisDb_LogoutAllRevocation"] = "9"
        };

        IConfiguration config = new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();

        AppConfig.Initialize(config);
    }
}
