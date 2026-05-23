using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundationTest;

[TestClass]
public sealed class DiscoveryApiTests
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
    /// 　リクエスト：Get Configuration を 標準入力 条件で実行
    /// 期待値
    /// 　Returns Oidc Discovery Metadata を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public void GetConfiguration_ReturnsOidcDiscoveryMetadata()
    {
        var controller = new OidcDiscoveryController();

        IActionResult result = controller.GetConfiguration();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(AppConfig.Issuer.TrimEnd('/'), body.Value<string>("issuer"));
        Assert.AreEqual($"{AppConfig.Issuer.TrimEnd('/')}/authorize", body.Value<string>("authorization_endpoint"));
        CollectionAssert.Contains(body["response_types_supported"]!.Values<string>().ToArray(), "code");
        CollectionAssert.Contains(body["grant_types_supported"]!.Values<string>().ToArray(), "authorization_code");
        CollectionAssert.Contains(body["token_endpoint_auth_methods_supported"]!.Values<string>().ToArray(), "none");
        CollectionAssert.Contains(body["token_endpoint_auth_methods_supported"]!.Values<string>().ToArray(), "client_secret_basic");
        CollectionAssert.Contains(body["code_challenge_methods_supported"]!.Values<string>().ToArray(), "S256");
        CollectionAssert.Contains(body["claims_supported"]!.Values<string>().ToArray(), "sub");
        CollectionAssert.Contains(body["claims_supported"]!.Values<string>().ToArray(), "email");
    }
}
