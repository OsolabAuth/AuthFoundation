using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundationTest;

[TestClass]
public sealed class DiscoveryApiTests
{
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 検証項目: OpenID Configurationが設計書のエンドポイント、PKCE S256、none/client_secret_basic、主要claimsを返すこと。
    /// </summary>
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
