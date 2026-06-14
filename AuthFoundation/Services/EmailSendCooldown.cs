using System.Collections.Concurrent;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class EmailSendCooldown
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _cooldowns = new(StringComparer.Ordinal);
    private readonly TimeSpan _cooldown;
    private readonly TimeProvider _timeProvider;
    private readonly IRedisStringStore? _redisStore;

    public EmailSendCooldown()
        : this(TimeSpan.FromSeconds(AppConfig.EmailSendCooldownSeconds), TimeProvider.System, null)
    {
    }

    public EmailSendCooldown(TimeSpan cooldown)
        : this(cooldown, TimeProvider.System, null)
    {
    }

    internal EmailSendCooldown(IRedisStringStore? redisStore)
        : this(TimeSpan.FromSeconds(AppConfig.EmailSendCooldownSeconds), TimeProvider.System, redisStore)
    {
    }

    internal EmailSendCooldown(TimeSpan cooldown, TimeProvider timeProvider, IRedisStringStore? redisStore)
    {
        if (cooldown <= TimeSpan.Zero)
        {
            throw Code.REQUEST_PARAMETER_ERROR;
        }

        _cooldown = cooldown;
        _timeProvider = timeProvider;
        _redisStore = redisStore;
    }

    public void EnsureCanSend(string purpose, string email)
    {
        string key = CooldownKey(purpose, email);
        DateTimeOffset now = _timeProvider.GetUtcNow();

        if (_redisStore is not null)
        {
            if (!_redisStore.SetStringIfNotExists(key, "1", _cooldown))
            {
                throw Code.TOO_MANY_REQUESTS;
            }

            return;
        }

        DateTimeOffset expiresAt = now.Add(_cooldown);
        DateTimeOffset value = _cooldowns.AddOrUpdate(
            key,
            _ => expiresAt,
            (_, current) => current <= now ? expiresAt : current);
        if (value > now && value != expiresAt)
        {
            throw Code.TOO_MANY_REQUESTS;
        }
    }

    private static string CooldownKey(string purpose, string email)
    {
        return $"auth:email_send_cooldown:{purpose}:{email.ToLowerInvariant()}";
    }
}
