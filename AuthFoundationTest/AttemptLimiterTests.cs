using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class AttemptLimiterTests
{
    /// <summary>
    /// 目的: Constructor / Rejects Invalid Max Attempts の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void Constructor_RejectsInvalidMaxAttempts()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(
            () => new AttemptLimiter(0, TimeSpan.FromMinutes(1)));

        Assert.AreEqual(Code.REQUEST_PARAMETER_ERROR.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 目的: Constructor / Rejects Invalid Window の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void Constructor_RejectsInvalidWindow()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(
            () => new AttemptLimiter(1, TimeSpan.Zero));

        Assert.AreEqual(Code.REQUEST_PARAMETER_ERROR.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 目的: Ensure Allowed / Allows Unknown Key の仕様を検証する。
    /// 入力値: 存在しないIDやメールアドレスなど、未知の対象を表す値。
    /// 期待値: Ensure Allowed / Allows Unknown Key の期待結果になること。
    /// </summary>
    [TestMethod]
    public void EnsureAllowed_AllowsUnknownKey()
    {
        var limiter = new AttemptLimiter(1, TimeSpan.FromMinutes(1));

        limiter.EnsureAllowed("unknown");
    }

    /// <summary>
    /// 目的: Record Failure / Blocks At Limit の仕様を検証する。
    /// 入力値: Record Failure / Blocks At Limit を確認するためにテスト内で作成したデータ。
    /// 期待値: Record Failure / Blocks At Limit の期待結果になること。
    /// </summary>
    [TestMethod]
    public void RecordFailure_BlocksAtLimit()
    {
        var limiter = new AttemptLimiter(2, TimeSpan.FromMinutes(1));
        limiter.RecordFailure("blocked");
        limiter.RecordFailure("blocked");

        ApiException error = Assert.ThrowsExactly<ApiException>(() => limiter.EnsureAllowed("blocked"));

        Assert.AreEqual(Code.UNAUTHORIZED.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 目的: Reset / Allows Blocked Key の仕様を検証する。
    /// 入力値: Reset / Allows Blocked Key を確認するためにテスト内で作成したデータ。
    /// 期待値: Reset / Allows Blocked Key の期待結果になること。
    /// </summary>
    [TestMethod]
    public void Reset_AllowsBlockedKey()
    {
        var limiter = new AttemptLimiter(1, TimeSpan.FromMinutes(1));
        limiter.RecordFailure("reset-target");

        limiter.Reset("reset-target");
        limiter.EnsureAllowed("reset-target");
    }

    /// <summary>
    /// あるアプリケーションインスタンスで記録した失敗回数を、別インスタンスの試行制限でもRedis共有状態として検出できることを確認する。
    /// </summary>
    [TestMethod]
    public void EnsureAllowed_UsesSharedRedisCounterAcrossInstances()
    {
        var redis = new FakeRedisStringStore();
        var writer = new AttemptLimiter(1, TimeSpan.FromMinutes(1), TimeProvider.System, redis);
        var reader = new AttemptLimiter(1, TimeSpan.FromMinutes(1), TimeProvider.System, redis);

        writer.RecordFailure("redis-blocked");
        ApiException error = Assert.ThrowsExactly<ApiException>(() => reader.EnsureAllowed("redis-blocked"));

        Assert.AreEqual(Code.UNAUTHORIZED.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 目的: Ensure Allowed / Removes Expired Counter の仕様を検証する。
    /// 入力値: 期限切れに変更したテストデータ。
    /// 期待値: Ensure Allowed / Removes Expired Counter の期待結果になること。
    /// </summary>
    [TestMethod]
    public void EnsureAllowed_RemovesExpiredCounter()
    {
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 6, 2, 0, 0, 0, TimeSpan.Zero));
        var limiter = new AttemptLimiter(1, TimeSpan.FromMinutes(1), time);
        limiter.RecordFailure("expired");
        time.Advance(TimeSpan.FromMinutes(2));

        limiter.EnsureAllowed("expired");
    }

    /// <summary>
    /// 目的: Record Failure / Resets Expired Counter の仕様を検証する。
    /// 入力値: 期限切れに変更したテストデータ。
    /// 期待値: Record Failure / Resets Expired Counter の期待結果になること。
    /// </summary>
    [TestMethod]
    public void RecordFailure_ResetsExpiredCounter()
    {
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 6, 2, 0, 0, 0, TimeSpan.Zero));
        var limiter = new AttemptLimiter(2, TimeSpan.FromMinutes(1), time);
        limiter.RecordFailure("expired-record");
        time.Advance(TimeSpan.FromMinutes(2));

        limiter.RecordFailure("expired-record");
        limiter.EnsureAllowed("expired-record");
        limiter.RecordFailure("expired-record");

        ApiException error = Assert.ThrowsExactly<ApiException>(() => limiter.EnsureAllowed("expired-record"));
        Assert.AreEqual(Code.UNAUTHORIZED.InternalCode, error.InternalCode);
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset _utcNow;

        public ManualTimeProvider(DateTimeOffset utcNow)
        {
            _utcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow()
        {
            return _utcNow;
        }

        public void Advance(TimeSpan delta)
        {
            _utcNow = _utcNow.Add(delta);
        }
    }

    private sealed class FakeRedisStringStore : IRedisStringStore
    {
        private readonly Dictionary<string, StoredValue> _values = new();

        public void SetString(string key, string value, TimeSpan expiresIn)
        {
            _values[key] = new StoredValue(value, DateTimeOffset.UtcNow.Add(expiresIn));
        }

        public string? GetString(string key)
        {
            if (!_values.TryGetValue(key, out StoredValue? stored) || stored.ExpiresAt <= DateTimeOffset.UtcNow)
            {
                return null;
            }

            return stored.Value;
        }

        public string? TakeString(string key)
        {
            string? value = GetString(key);
            _ = _values.Remove(key);
            return value;
        }

        public bool DeleteString(string key)
        {
            return _values.Remove(key);
        }
    }

    private sealed record StoredValue(string Value, DateTimeOffset ExpiresAt);
}
