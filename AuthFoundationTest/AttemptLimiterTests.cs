using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class AttemptLimiterTests
{
    /// <summary>
    /// 逶ｮ逧・ Constructor / Rejects Invalid Max Attempts 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝輔か繝ｼ繝槭ャ繝井ｸ肴ｭ｣縺ｾ縺滂ｿｽE讓ｩ髯仙､厄ｿｽE蜈･蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void Constructor_RejectsInvalidMaxAttempts()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(
            () => TestServices.CreateAttemptLimiter(0, TimeSpan.FromMinutes(1)));

        Assert.AreEqual(Code.REQUEST_PARAMETER_ERROR.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 逶ｮ逧・ Constructor / Rejects Invalid Window 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝輔か繝ｼ繝槭ャ繝井ｸ肴ｭ｣縺ｾ縺滂ｿｽE讓ｩ髯仙､厄ｿｽE蜈･蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void Constructor_RejectsInvalidWindow()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(
            () => TestServices.CreateAttemptLimiter(1, TimeSpan.Zero));

        Assert.AreEqual(Code.REQUEST_PARAMETER_ERROR.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 逶ｮ逧・ Ensure Allowed / Allows Unknown Key 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蟄伜惠縺励↑縺ИD繧・・ｽ・ｽ繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｪ縺ｩ縲∵悴遏･縺ｮ蟇ｾ雎｡繧定｡ｨ縺吝､縲・
    /// 譛溷ｾ・・ｽ・ｽ: Ensure Allowed / Allows Unknown Key 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void EnsureAllowed_AllowsUnknownKey()
    {
        var limiter = TestServices.CreateAttemptLimiter(1, TimeSpan.FromMinutes(1));

        limiter.EnsureAllowed("unknown");
    }

    /// <summary>
    /// 逶ｮ逧・ Record Failure / Blocks At Limit 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Record Failure / Blocks At Limit 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Record Failure / Blocks At Limit 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void RecordFailure_BlocksAtLimit()
    {
        var limiter = TestServices.CreateAttemptLimiter(2, TimeSpan.FromMinutes(1));
        limiter.RecordFailure("blocked");
        limiter.RecordFailure("blocked");

        ApiException error = Assert.ThrowsExactly<ApiException>(() => limiter.EnsureAllowed("blocked"));

        Assert.AreEqual(Code.UNAUTHORIZED.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 逶ｮ逧・ Reset / Allows Blocked Key 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Reset / Allows Blocked Key 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Reset / Allows Blocked Key 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void Reset_AllowsBlockedKey()
    {
        var limiter = TestServices.CreateAttemptLimiter(1, TimeSpan.FromMinutes(1));
        limiter.RecordFailure("reset-target");

        limiter.Reset("reset-target");
        limiter.EnsureAllowed("reset-target");
    }

    /// <summary>
    /// 縺ゅｋ繧｢繝励Μ繧ｱ繝ｼ繧ｷ繝ｧ繝ｳ繧､繝ｳ繧ｹ繧ｿ繝ｳ繧ｹ縺ｧ險倬鹸縺励◆螟ｱ謨怜屓謨ｰ繧偵∝挨繧､繝ｳ繧ｹ繧ｿ繝ｳ繧ｹ縺ｮ隧ｦ陦悟宛髯舌〒繧３edis蜈ｱ譛臥憾諷九→縺励※讀懶ｿｽE縺ｧ縺阪ｋ縺薙→繧堤｢ｺ隱阪☆繧九・
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
    /// 逶ｮ逧・ Ensure Allowed / Removes Expired Counter 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 譛滄剞蛻・・ｽ・ｽ縺ｫ螟画峩縺励◆繝・・ｽ・ｽ繝医ョ繝ｼ繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Ensure Allowed / Removes Expired Counter 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void EnsureAllowed_RemovesExpiredCounter()
    {
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 6, 2, 0, 0, 0, TimeSpan.Zero));
        var limiter = TestServices.CreateAttemptLimiter(1, TimeSpan.FromMinutes(1), time);
        limiter.RecordFailure("expired");
        time.Advance(TimeSpan.FromMinutes(2));

        limiter.EnsureAllowed("expired");
    }

    /// <summary>
    /// 逶ｮ逧・ Record Failure / Resets Expired Counter 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 譛滄剞蛻・・ｽ・ｽ縺ｫ螟画峩縺励◆繝・・ｽ・ｽ繝医ョ繝ｼ繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Record Failure / Resets Expired Counter 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void RecordFailure_ResetsExpiredCounter()
    {
        var time = new ManualTimeProvider(new DateTimeOffset(2026, 6, 2, 0, 0, 0, TimeSpan.Zero));
        var limiter = TestServices.CreateAttemptLimiter(2, TimeSpan.FromMinutes(1), time);
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

        public bool SetStringIfNotExists(string key, string value, TimeSpan expiresIn)
        {
            if (GetString(key) is not null)
            {
                return false;
            }

            SetString(key, value, expiresIn);
            return true;
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
