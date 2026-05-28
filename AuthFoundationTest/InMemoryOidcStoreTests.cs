using System.Collections.Concurrent;
using System.Reflection;
using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class InMemoryOidcStoreTests
{
    [TestMethod]
    public void TakeRequest_RemovesAndReturnsKnownRequest()
    {
        var store = new InMemoryOidcStore();
        AuthorizationRequestRecord request = CreateRequest(store);

        AuthorizationRequestRecord actual = store.TakeRequest(request.RequestId);

        Assert.AreEqual(request.RequestId, actual.RequestId);
        Assert.AreEqual(AppConfig.DevelopmentClientId, actual.ClientId);
        Assert.ThrowsExactly<ApiException>(() => store.TakeRequest(request.RequestId));
    }

    [TestMethod]
    public void TakeRequest_RejectsUnknownRequest()
    {
        var store = new InMemoryOidcStore();

        ApiException error = Assert.ThrowsExactly<ApiException>(() => store.TakeRequest("missing"));

        Assert.AreEqual(Code.UNAUTHORIZED.InternalCode, error.InternalCode);
    }

    [TestMethod]
    public void TakeRequest_RejectsExpiredRequest()
    {
        var store = new InMemoryOidcStore();
        AuthorizationRequestRecord request = CreateRequest(store);
        Requests(store)[request.RequestId] = request with { ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) };

        ApiException error = Assert.ThrowsExactly<ApiException>(() => store.TakeRequest(request.RequestId));

        Assert.AreEqual(Code.UNAUTHORIZED.InternalCode, error.InternalCode);
    }

    [TestMethod]
    public void TakeCode_RemovesAndReturnsKnownCode()
    {
        var store = new InMemoryOidcStore();
        AuthorizationCodeRecord code = CreateCode(store);

        AuthorizationCodeRecord actual = store.TakeCode(code.Code);

        Assert.AreEqual(code.Code, actual.Code);
        Assert.AreEqual("subject_1", actual.Subject);
        Assert.ThrowsExactly<ApiException>(() => store.TakeCode(code.Code));
    }

    [TestMethod]
    public void TakeCode_RejectsUnknownCode()
    {
        var store = new InMemoryOidcStore();

        ApiException error = Assert.ThrowsExactly<ApiException>(() => store.TakeCode("missing"));

        Assert.AreEqual("invalid_grant", error.Error);
        Assert.AreEqual("invalid authorization code", error.ErrorDescription);
    }

    [TestMethod]
    public void TakeCode_RejectsExpiredCode()
    {
        var store = new InMemoryOidcStore();
        AuthorizationCodeRecord code = CreateCode(store);
        Codes(store)[code.Code] = code with { ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) };

        ApiException error = Assert.ThrowsExactly<ApiException>(() => store.TakeCode(code.Code));

        Assert.AreEqual("invalid_grant", error.Error);
        Assert.AreEqual("invalid authorization code", error.ErrorDescription);
    }

    private static AuthorizationCodeRecord CreateCode(InMemoryOidcStore store)
    {
        return store.CreateCode(CreateRequest(store), "subject_1", "subject@example.com", "Subject One");
    }

    private static AuthorizationRequestRecord CreateRequest(InMemoryOidcStore store)
    {
        return store.CreateRequest(
            AppConfig.DevelopmentClientId,
            AppConfig.DevelopmentRedirectUri,
            "openid profile email",
            "state_1",
            "nonce_1",
            PkceUtil.CreateS256Challenge("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"));
    }

    private static ConcurrentDictionary<string, AuthorizationRequestRecord> Requests(InMemoryOidcStore store)
    {
        return PrivateField<ConcurrentDictionary<string, AuthorizationRequestRecord>>(store, "_requests");
    }

    private static ConcurrentDictionary<string, AuthorizationCodeRecord> Codes(InMemoryOidcStore store)
    {
        return PrivateField<ConcurrentDictionary<string, AuthorizationCodeRecord>>(store, "_codes");
    }

    private static T PrivateField<T>(object target, string name)
    {
        FieldInfo? field = target.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.IsNotNull(field);
        object? value = field.GetValue(target);
        Assert.IsInstanceOfType<T>(value);
        return (T)value;
    }
}
