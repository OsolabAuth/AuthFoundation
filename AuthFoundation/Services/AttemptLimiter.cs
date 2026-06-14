using System.Collections.Concurrent;
using System.Text.Json;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class AttemptLimiter
{
    private static readonly JsonSerializerOptions JsonOptions = new();
    private readonly ConcurrentDictionary<string, AttemptCounter> _counters = new(StringComparer.Ordinal);
    private readonly int _maxAttempts;
    private readonly TimeSpan _window;
    private readonly TimeProvider _timeProvider;
    private readonly IRedisStringStore? _redisStore;

    public AttemptLimiter()
        : this(AppConfig.AttemptLimitMaxAttempts, TimeSpan.FromMinutes(AppConfig.AttemptLimitWindowMinutes))
    {
    }

    public AttemptLimiter(int maxAttempts, TimeSpan window)
        : this(maxAttempts, window, TimeProvider.System)
    {
    }

    public AttemptLimiter(int maxAttempts, TimeSpan window, TimeProvider timeProvider)
        : this(maxAttempts, window, timeProvider, null)
    {
    }

    internal AttemptLimiter(IRedisStringStore? redisStore)
        : this(AppConfig.AttemptLimitMaxAttempts, TimeSpan.FromMinutes(AppConfig.AttemptLimitWindowMinutes), TimeProvider.System, redisStore)
    {
    }

    internal AttemptLimiter(int maxAttempts, TimeSpan window, TimeProvider timeProvider, IRedisStringStore? redisStore)
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
        AttemptCounter? counter = GetCounter(key);
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
        if (_redisStore is null)
        {
            _counters.AddOrUpdate(
                key,
                _ => new AttemptCounter(1, now.Add(_window)),
                (_, counter) => counter.ExpiresAt <= now
                    ? new AttemptCounter(1, now.Add(_window))
                    : counter with { Failures = counter.Failures + 1 });
            return;
        }

        AttemptCounter? current = GetCounter(key);
        AttemptCounter next = current is null || current.ExpiresAt <= now
            ? new AttemptCounter(1, now.Add(_window))
            : current with { Failures = current.Failures + 1 };
        _redisStore.SetString(CounterKey(key), JsonSerializer.Serialize(next, JsonOptions), next.ExpiresAt - now);
    }

    public void Reset(string key)
    {
        DeleteCounter(key);
    }

    private AttemptCounter? GetCounter(string key)
    {
        if (_redisStore is null)
        {
            return _counters.TryGetValue(key, out AttemptCounter? counter) ? counter : null;
        }

        string? value = _redisStore.GetString(CounterKey(key));
        return string.IsNullOrWhiteSpace(value) ? null : JsonSerializer.Deserialize<AttemptCounter>(value, JsonOptions);
    }

    private void DeleteCounter(string key)
    {
        if (_redisStore is null)
        {
            _counters.TryRemove(key, out _);
            return;
        }

        _redisStore.DeleteString(CounterKey(key));
    }

    private static string CounterKey(string key)
    {
        return $"auth:attempt:{key}";
    }
}

public sealed record AttemptCounter(int Failures, DateTimeOffset ExpiresAt);
