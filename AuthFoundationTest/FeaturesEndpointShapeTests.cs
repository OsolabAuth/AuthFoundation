using AuthFoundation.Controllers;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundationTest;

[TestClass]
public sealed class FeaturesEndpointShapeTests
{
    /// <summary>
    /// 目的: 実装済み機能一覧APIが公開機能カタログを返すことを検証する。
    /// 入力値: GET /features を呼び出す。
    /// 期待値: サービス名、状態、実装済み機能の識別子と説明が返ること。
    /// </summary>
    [TestMethod]
    public void Get_ReturnsImplementedFeatureCatalog()
    {
        var controller = new FeaturesController();

        var ok = controller.Get() as OkObjectResult;

        Assert.IsNotNull(ok);
        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("AuthFoundation", EndpointTestHelper.ReadProperty<string>(ok.Value, "service"));
        Assert.AreEqual("ok", EndpointTestHelper.ReadProperty<string>(ok.Value, "status"));

        FeatureInfo[] features = EndpointTestHelper.ReadProperty<FeatureInfo[]>(ok.Value, "features");
        string[] keys = features.Select(feature => feature.Key).ToArray();
        CollectionAssert.AreEqual(new[]
        {
            "service.version",
            "oidc.discovery",
            "oidc.authorization_code_pkce",
            "oidc.userinfo",
            "account.signup_terms",
            "mfa.step_up",
            "account.password_change",
            "account.password_reset",
            "session.logout_revoke",
            "account.withdrawal",
            "agent.delegated_auth"
        }, keys);

        Assert.IsTrue(features.All(feature => feature.Status == "available"));
        Assert.IsTrue(features.All(feature => !string.IsNullOrWhiteSpace(feature.Name)));
        Assert.IsTrue(features.All(feature => !string.IsNullOrWhiteSpace(feature.Description)));
    }
}
