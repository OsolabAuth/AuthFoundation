using System.Collections.Concurrent;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class AttemptLimiter
{
    private readonly ConcurrentDictionary<string, AttemptCounter> _counters = new(StringComparer.Ordinal);
    private readonly int _maxAttempts;
    private readonly TimeSpan _window;
    private readonly TimeProvider _timeProvider;

    public AttemptLimiter()
        : this(AppConfig.AttemptLimitMaxAttempts, TimeSpan.FromMinutes(AppConfig.AttemptLimitWindowMinutes))
    {
    }

    public AttemptLimiter(int maxAttempts, TimeSpan window)
        : this(maxAttempts, window, TimeProvider.System)
    {
    }

    public AttemptLimiter(int maxAttempts, TimeSpan window, TimeProvider timeProvider)
    {
        if (maxAttempts <= 0 || window <= TimeSpan.Zero)
        {
            throw Code.REQUEST_PARAMETER_ERROR;
        }

        _maxAttempts = maxAttempts;
        _window = window;
        _timeProvider = timeProvider;
    }

    public void EnsureAllowed(string key)
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        if (_counters.TryGetValue(key, out AttemptCounter? counter) && counter.ExpiresAt <= now)
        {
            _counters.TryRemove(key, out _);
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
        _counters.AddOrUpdate(
            key,
            _ => new AttemptCounter(1, now.Add(_window)),
            (_, counter) => counter.ExpiresAt <= now
                ? new AttemptCounter(1, now.Add(_window))
                : counter with { Failures = counter.Failures + 1 });
    }

    public void Reset(string key)
    {
        _counters.TryRemove(key, out _);
    }
}

public sealed record AttemptCounter(int Failures, DateTimeOffset ExpiresAt);
