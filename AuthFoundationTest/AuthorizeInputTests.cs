using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Http;

namespace AuthFoundationTest;

[TestClass]
public sealed class AuthorizeInputTests
{
    [TestMethod]
    public void Create_ReadsAuthorizeQueryAndBuildsAuthorizationSession()
    {
        var context = new DefaultHttpContext();
        context.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["response_type"] = "code",
            ["client_id"] = "12345678901234567890123456789012",
            ["redirect_uri"] = "https://client.example.com/callback",
            ["state"] = "state-1",
            ["scope"] = "openid email",
            ["code_challenge_method"] = "S256",
            ["code_challenge"] = new string('a', 43),
            ["nonce"] = "nonce-1"
        });

        AuthorizeController.Input input = AuthorizeController.Input.Create(context);
        input.Validate();
        AuthorizationSession session = input.ToAuthorizationSession();

        Assert.AreEqual("code", session.ResponseType);
        Assert.AreEqual("12345678901234567890123456789012", session.ClientId);
        Assert.AreEqual("https://client.example.com/callback", session.RedirectUri);
        Assert.AreEqual("openid email", session.Scope);
        Assert.AreEqual("S256", session.CodeChallengeMethod);
    }

    [TestMethod]
    public void Validate_ThrowsApiExceptionForIllegalRedirectUri()
    {
        var input = new AuthorizeController.Input
        {
            ResponseType = "code",
            ClientId = "12345678901234567890123456789012",
            RedirectUri = "http://example.com/callback",
            State = "state-1",
            Scope = "openid",
            CodeChallengeMethod = "S256",
            CodeChallenge = new string('a', 43),
            Nonce = "nonce-1"
        };

        ApiException ex = Assert.ThrowsExactly<ApiException>(input.Validate);
        Assert.AreEqual(Code.REQUEST_PARAMETER_ERROR.Code, ex.Code);
    }
}
