using AuthFoundation.Controllers.Auth;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundationTest;

[TestClass]
public sealed class JwksApiTests
{
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 検証項目: GET /jwks が公開鍵のみを返し、RSA/RS256/sigのJWK形式を満たすこと。
    /// </summary>
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
