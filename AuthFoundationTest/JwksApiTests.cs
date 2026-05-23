using AuthFoundation.Controllers.Auth;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundationTest;

[TestClass]
public sealed class JwksApiTests
{
    /// <summary>
    /// 前提条件
    /// 　DB：テスト実行前の初期データを投入可能
    /// 　リクエスト：なし（テスト初期化処理）
    /// 期待値
    /// 　共通設定とテスト実行環境が初期化される
    /// </summary>
    /// <returns></returns>
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get Jwks を 標準入力 条件で実行
    /// 期待値
    /// 　Returns Public Rsa Signing Keys Only を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task GetJwks_ReturnsPublicRsaSigningKeysOnly()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var controller = new JwksController(SigningTestHelper.CreateSigningService());

        IActionResult result = await controller.GetJwks();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        var body = ControllerTestHelper.ToJObject(result);
        Assert.IsTrue(body["keys"]!.Any());

        var key = body["keys"]!.First!;
        Assert.AreEqual("RSA", key.Value<string>("kty"));
        Assert.AreEqual("RS256", key.Value<string>("alg"));
        Assert.AreEqual("sig", key.Value<string>("use"));
        Assert.IsFalse(string.IsNullOrWhiteSpace(key.Value<string>("kid")));
        Assert.IsFalse(string.IsNullOrWhiteSpace(key.Value<string>("n")));
        Assert.IsFalse(string.IsNullOrWhiteSpace(key.Value<string>("e")));
        Assert.IsNull(key["private_key"]);
        Assert.IsNull(key["d"]);
    }
}
