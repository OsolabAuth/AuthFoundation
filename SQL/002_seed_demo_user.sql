BEGIN TRAN;

IF NOT EXISTS (
    SELECT 1 FROM [auth].[osolab_user] WHERE [email] = 'demo@example.com'
)
BEGIN
    INSERT INTO [auth].[osolab_user]
    (
        [osolab_id],
        [email],
        [password],
        [nonce],
        [create_datetime],
        [update_datetime],
        [status]
    )
    VALUES
    (
        'USER000000000001',
        'demo@example.com',
        'EF9CBEFD4A3B7809088010182B057FB1825E6236A618E7492474AE709F7E4B84',
        'N0NCE123',
        SYSDATETIME(),
        SYSDATETIME(),
        1
    );
END;

IF NOT EXISTS (
    SELECT 1
    FROM [auth].[user_info]
    WHERE [osolab_id] = 'USER000000000001'
      AND [client_id] = '00000000000000000000000000000000'
      AND [data_key] = 'email'
)
BEGIN
    INSERT INTO [auth].[user_info]
    (
        [osolab_id],
        [client_id],
        [data_key],
        [data_value],
        [create_datetime],
        [update_datetime],
        [status]
    )
    VALUES
    ('USER000000000001', '00000000000000000000000000000000', 'sub', 'USER000000000001', SYSDATETIME(), SYSDATETIME(), 1),
    ('USER000000000001', '00000000000000000000000000000000', 'email', 'demo@example.com', SYSDATETIME(), SYSDATETIME(), 1),
    ('USER000000000001', '00000000000000000000000000000000', 'name', 'Demo User', SYSDATETIME(), SYSDATETIME(), 1),
    ('USER000000000001', '00000000000000000000000000000000', 'preferred_username', 'demo', SYSDATETIME(), SYSDATETIME(), 1),
    ('USER000000000001', '00000000000000000000000000000000', 'latest_login_datetime', CONVERT(varchar(30), SYSUTCDATETIME(), 126), SYSDATETIME(), SYSDATETIME(), 1),
    ('USER000000000001', '00000000000000000000000000000000', 'email_verified', 'true', SYSDATETIME(), SYSDATETIME(), 1);
END;

COMMIT TRAN;
