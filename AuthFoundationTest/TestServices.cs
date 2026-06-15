using AuthFoundation.Services;

namespace AuthFoundationTest;

internal static class TestServices
{
    public static TestRedisStringStore CreateRedis()
    {
        return new TestRedisStringStore();
    }

    public static AttemptLimiter CreateAttemptLimiter()
    {
        return new AttemptLimiter(new TestRedisStringStore());
    }

    public static AttemptLimiter CreateAttemptLimiter(int maxAttempts, TimeSpan window)
    {
        return new AttemptLimiter(maxAttempts, window, TimeProvider.System, new TestRedisStringStore());
    }

    public static AttemptLimiter CreateAttemptLimiter(int maxAttempts, TimeSpan window, TimeProvider timeProvider)
    {
        return new AttemptLimiter(maxAttempts, window, timeProvider, new TestRedisStringStore());
    }

    public static EmailSendCooldown CreateEmailSendCooldown(TimeSpan cooldown)
    {
        return new EmailSendCooldown(cooldown, new TestRedisStringStore());
    }

    public static StepUpService CreateStepUpService(IUserStore users)
    {
        return CreateStepUpService(users, new RecordingEmailSender());
    }

    public static StepUpService CreateStepUpService(IUserStore users, IEmailSender emailSender)
    {
        TestRedisStringStore redis = new();
        return new StepUpService(
            users,
            emailSender,
            new AttemptLimiter(redis),
            new EmailSendCooldown(redis),
            redis);
    }

    public static StepUpService CreateStepUpService(IUserStore users, IEmailSender emailSender, AttemptLimiter attempts)
    {
        TestRedisStringStore redis = new();
        return new StepUpService(
            users,
            emailSender,
            attempts,
            new EmailSendCooldown(redis),
            redis);
    }

    public static StepUpService CreateStepUpService(
        IUserStore users,
        IEmailSender emailSender,
        AttemptLimiter attempts,
        IRedisStringStore redis)
    {
        return new StepUpService(
            users,
            emailSender,
            attempts,
            new EmailSendCooldown(redis),
            redis);
    }

    public static StepUpService CreateStepUpService(
        IUserStore users,
        IEmailSender emailSender,
        AttemptLimiter attempts,
        EmailSendCooldown cooldown,
        IRedisStringStore redis)
    {
        return new StepUpService(users, emailSender, attempts, cooldown, redis);
    }

    public static SignupSessionService CreateSignupSessionService(IEmailSender emailSender)
    {
        TestRedisStringStore redis = new();
        return new SignupSessionService(emailSender, new AttemptLimiter(redis), new EmailSendCooldown(redis), redis);
    }

    public static SignupSessionService CreateSignupSessionService(
        IEmailSender emailSender,
        AttemptLimiter attempts,
        IRedisStringStore redis)
    {
        return new SignupSessionService(emailSender, attempts, new EmailSendCooldown(redis), redis);
    }

    private sealed class RecordingEmailSender : IEmailSender
    {
        public void SendMfaCode(string email, string code, DateTimeOffset expiresAt)
        {
        }
    }
}
