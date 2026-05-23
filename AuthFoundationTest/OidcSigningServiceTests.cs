using System.Text;
using AuthFoundation.Common;
using AuthFoundation.Models;
using AuthFoundation.Session;
using AuthFoundationTest.TestSupport;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json.Linq;

namespace AuthFoundationTest;

[TestClass]
[DoNotParallelize]
public sealed class OidcSigningServiceTests
{
    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Create Id Token Async を When Reload Interval Not Elapsed 条件で実行
    /// 期待値
    /// 　Keeps Cached Signing Key を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task CreateIdTokenAsync_WhenReloadIntervalNotElapsed_KeepsCachedSigningKey()
    {
        AppConfigTestHelper.Initialize(new Dictionary<string, string?>
        {
            ["JwkSigningKeyReloadSec"] = "600"
        });

        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        OidcSigningService service = SigningTestHelper.CreateSigningService();
        string firstKid = await GetCurrentKidAsync(service);
        string rotatedKid = await InsertNewerActiveKeyAsync(context, firstKid);

        string idToken = await service.CreateIdTokenAsync(CreateCodeSession(), new[] { Code.Scope.OPENID, Code.Scope.EMAIL });
        string idTokenKid = GetTokenKid(idToken);

        Assert.AreEqual(firstKid, idTokenKid);
        Assert.AreNotEqual(rotatedKid, idTokenKid);
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Create Id Token Async を When Reload Interval Zero 条件で実行
    /// 期待値
    /// 　Uses Latest Signing Key を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task CreateIdTokenAsync_WhenReloadIntervalZero_UsesLatestSigningKey()
    {
        AppConfigTestHelper.Initialize(new Dictionary<string, string?>
        {
            ["JwkSigningKeyReloadSec"] = "0"
        });

        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        OidcSigningService service = SigningTestHelper.CreateSigningService();
        string firstKid = await GetCurrentKidAsync(service);
        string rotatedKid = await InsertNewerActiveKeyAsync(context, firstKid);

        string idToken = await service.CreateIdTokenAsync(CreateCodeSession(), new[] { Code.Scope.OPENID, Code.Scope.EMAIL });
        string idTokenKid = GetTokenKid(idToken);
        string jwksTopKid = await GetCurrentKidAsync(service);

        Assert.AreEqual(rotatedKid, idTokenKid);
        Assert.AreEqual(rotatedKid, jwksTopKid);
    }

    private static async Task<string> GetCurrentKidAsync(OidcSigningService service)
    {
        JObject jwks = JObject.FromObject(await service.CreateJwksAsync());
        return jwks["keys"]?.First?["kid"]?.Value<string>() ?? string.Empty;
    }

    private static async Task<string> InsertNewerActiveKeyAsync(AuthFoundation.Data.OsolabAuthContext context, string sourceKid)
    {
        jwk_master source = await context.jwk_masters
            .AsNoTracking()
            .Where(x => x.kid == sourceKid && x.status == Code.Status.ACTIVE)
            .SingleAsync();

        string suffix = Guid.NewGuid().ToString("N")[..10];
        string baseKid = source.kid.Length > 48 ? source.kid[..48] : source.kid;
        string rotatedKid = $"{baseKid}-rot-{suffix}";

        DateTime now = DateTime.UtcNow.AddSeconds(1);
        context.jwk_masters.Add(new jwk_master
        {
            kid = rotatedKid,
            kty = source.kty,
            alg = source.alg,
            key_use = source.key_use,
            public_n = source.public_n,
            public_e = source.public_e,
            private_key_ciphertext = source.private_key_ciphertext.ToArray(),
            private_key_iv = source.private_key_iv.ToArray(),
            private_key_tag = source.private_key_tag.ToArray(),
            create_datetime = now,
            update_datetime = now,
            status = Code.Status.ACTIVE
        });
        await context.SaveChangesAsync();

        return rotatedKid;
    }

    private static AuthCodeSession CreateCodeSession()
    {
        return new AuthCodeSession
        {
            OsolabId = ApiTestData.NewOsolabId(),
            ClientId = ApiTestData.NewClientId(),
            Email = $"signing-{Guid.NewGuid():N}@example.com",
            Nonce = "nonce-signing-test"
        };
    }

    private static string GetTokenKid(string idToken)
    {
        string[] parts = idToken.Split('.');
        Assert.AreEqual(3, parts.Length);

        string headerJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
        JObject header = JObject.Parse(headerJson);
        return header.Value<string>("kid") ?? string.Empty;
    }

    private static byte[] Base64UrlDecode(string value)
    {
        string normalized = value.Replace('-', '+').Replace('_', '/');
        int mod = normalized.Length % 4;
        if (mod == 2)
        {
            normalized += "==";
        }
        else if (mod == 3)
        {
            normalized += "=";
        }

        return Convert.FromBase64String(normalized);
    }
}
