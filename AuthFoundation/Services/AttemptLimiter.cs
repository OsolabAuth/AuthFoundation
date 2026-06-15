using AuthFoundation.Common;
using AuthFoundation.Session;

namespace AuthFoundation.Services;

public sealed class AttemptLimiter
{
    private readonly int _maxAttempts;
    private readonly TimeSpan _window;
    private readonly TimeProvider _timeProvider;
    private readonly IRedisStringStore _redisStore;

    internal AttemptLimiter(IRedisStringStore redisStore)
        : this(AppConfig.AttemptLimitMaxAttempts, TimeSpan.FromMinutes(AppConfig.AttemptLimitWindowMinutes), TimeProvider.System, redisStore)
    {
    }

    internal AttemptLimiter(int maxAttempts, TimeSpan window, TimeProvider timeProvider, IRedisStringStore redisStore)
    {
        if (maxAttempts <= 0 || window <= TimeSpan.Zero)
        {
            throw Code.REQUEST_PARAMETER_ERROR;
        }

        _maxAttempts = maxAttempts;
        _window = window;
        _timeProvider = timeProvider;
        _redisStore = redisStore;
    }

    public void EnsureAllowed(string key)
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        AttemptCounterSession? counter = GetCounter(key);
        if (counter is not null && counter.ExpiresAt <= now)
        {
            DeleteCounter(key);
            return;
        }

        if (counter is not null && counter.Failures >= _maxAttempts)
        {
            throw Code.UNAUTHORIZED;
        }
    }

    public void RecordFailure(string key)
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        AttemptCounterSession? current = GetCounter(key);
        AttemptCounterSession next = current is null || current.ExpiresAt <= now
            ? new AttemptCounterSession { Failures = 1, ExpiresAt = now.Add(_window) }
            : new AttemptCounterSession { Failures = current.Failures + 1, ExpiresAt = current.ExpiresAt };
        _redisStore.SetString(
            AttemptCounterSession.GetRedisKey(key),
            RedisSessionJson.Serialize(next),
            next.ExpiresAt - now);
    }

    public void Reset(string key)
    {
        DeleteCounter(key);
    }

    private AttemptCounterSession? GetCounter(string key)
    {
        string? value = _redisStore.GetString(AttemptCounterSession.GetRedisKey(key));
        return RedisSessionJson.Deserialize<AttemptCounterSession>(value);
    }

    private void DeleteCounter(string key)
    {
        _redisStore.DeleteString(AttemptCounterSession.GetRedisKey(key));
    }
}
