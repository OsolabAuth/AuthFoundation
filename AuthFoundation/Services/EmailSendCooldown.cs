using AuthFoundation.Common;
using AuthFoundation.Session;

namespace AuthFoundation.Services;

public sealed class EmailSendCooldown
{
    private readonly TimeSpan _cooldown;
    private readonly IRedisStringStore _redisStore;

    internal EmailSendCooldown(IRedisStringStore redisStore)
        : this(TimeSpan.FromSeconds(AppConfig.EmailSendCooldownSeconds), redisStore)
    {
    }

    internal EmailSendCooldown(TimeSpan cooldown, IRedisStringStore redisStore)
    {
        if (cooldown <= TimeSpan.Zero)
        {
            throw Code.REQUEST_PARAMETER_ERROR;
        }

        _cooldown = cooldown;
        _redisStore = redisStore;
    }

    public void EnsureCanSend(string purpose, string email)
    {
        string key = EmailSendCooldownSession.GetRedisKey(purpose, email);
        if (!_redisStore.SetStringIfNotExists(key, EmailSendCooldownSession.Value, _cooldown))
        {
            throw Code.TOO_MANY_REQUESTS;
        }
    }
}
