using AuthFoundation.Controllers;
using AuthFoundation.Contracts;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundationTest;

[TestClass]
public sealed class FeaturesEndpointShapeTests
{
    /// <summary>
    /// 逶ｮ逧・ 螳溯｣・・ｽ・ｽ縺ｿ讖滂ｿｽE荳隕ｧAPI縺鯉ｿｽE髢区ｩ滂ｿｽE繧ｫ繧ｿ繝ｭ繧ｰ繧定ｿ斐☆縺薙→繧呈､懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: GET /features 繧貞他縺ｳ蜃ｺ縺吶・
    /// 譛溷ｾ・・ｽ・ｽ: 繧ｵ繝ｼ繝薙せ蜷阪∫憾諷九∝ｮ溯｣・・ｽ・ｽ縺ｿ讖滂ｿｽE縺ｮ隴伜挨蟄舌→隱ｬ譏弱′霑斐ｋ縺薙→縲・
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
