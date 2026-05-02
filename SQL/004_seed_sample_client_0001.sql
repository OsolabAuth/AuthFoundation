BEGIN TRAN;

DECLARE @ClientId varchar(32) = '00000000000000000000000000000001';
DECLARE @Now datetime2(0) = SYSDATETIME();

-- client_master
IF NOT EXISTS (
    SELECT 1
    FROM [auth].[client_master]
    WHERE [client_id] = @ClientId
)
BEGIN
    INSERT INTO [auth].[client_master]
    (
        [client_id],
        [client_name],
        [client_secret],
        [create_datetime],
        [update_datetime],
        [status]
    )
    VALUES
    (
        @ClientId,
        'SampleClient-0001',
        '1111111111111111111111111111111111111111111111111111111111111111',
        @Now,
        @Now,
        1
    );
END;

-- client_data_key
INSERT INTO [auth].[client_data_key] ([client_id], [data_key], [create_datetime], [update_datetime], [status])
SELECT @ClientId, d.[data_key], @Now, @Now, 1
FROM [auth].[data_key_master] d
WHERE d.[data_key] IN ('sub', 'email', 'name', 'preferred_username', 'latest_login_datetime', 'email_verified')
  AND NOT EXISTS (
      SELECT 1
      FROM [auth].[client_data_key] cdk
      WHERE cdk.[client_id] = @ClientId
        AND cdk.[data_key] = d.[data_key]
  );

-- client_scopes (required)
IF NOT EXISTS (SELECT 1 FROM [auth].[client_scopes] WHERE [client_id] = @ClientId AND [scope] = 'openid')
BEGIN
    INSERT INTO [auth].[client_scopes] ([client_id], [scope], [required], [create_datetime], [update_datetime], [status])
    VALUES (@ClientId, 'openid', 1, @Now, @Now, 1);
END;

IF NOT EXISTS (SELECT 1 FROM [auth].[client_scopes] WHERE [client_id] = @ClientId AND [scope] = 'profile')
BEGIN
    INSERT INTO [auth].[client_scopes] ([client_id], [scope], [required], [create_datetime], [update_datetime], [status])
    VALUES (@ClientId, 'profile', 1, @Now, @Now, 1);
END;

IF NOT EXISTS (SELECT 1 FROM [auth].[client_scopes] WHERE [client_id] = @ClientId AND [scope] = 'email')
BEGIN
    INSERT INTO [auth].[client_scopes] ([client_id], [scope], [required], [create_datetime], [update_datetime], [status])
    VALUES (@ClientId, 'email', 1, @Now, @Now, 1);
END;

-- client_terms
IF NOT EXISTS (
    SELECT 1
    FROM [auth].[client_terms]
    WHERE [client_id] = @ClientId
      AND [term_version] = 'v1'
)
BEGIN
    INSERT INTO [auth].[client_terms]
    (
        [client_id],
        [term_version],
        [term_title],
        [term_url],
        [required],
        [create_datetime],
        [update_datetime],
        [status]
    )
    VALUES
    (
        @ClientId,
        'v1',
        N'Sample Client 利用規約',
        N'https://example.local/terms/sample-client-0001/v1',
        1,
        @Now,
        @Now,
        1
    );
END;

-- demo user info for this client
IF EXISTS (SELECT 1 FROM [auth].[osolab_user] WHERE [osolab_id] = 'USER000000000001')
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
    SELECT 'USER000000000001', @ClientId, x.[data_key], x.[data_value], @Now, @Now, 1
    FROM (VALUES
        ('sub', 'USER000000000001'),
        ('email', 'demo@example.com'),
        ('name', 'Demo User'),
        ('preferred_username', 'demo'),
        ('latest_login_datetime', CONVERT(varchar(30), SYSUTCDATETIME(), 126)),
        ('email_verified', 'true')
    ) AS x([data_key], [data_value])
    WHERE NOT EXISTS (
        SELECT 1
        FROM [auth].[user_info] ui
        WHERE ui.[osolab_id] = 'USER000000000001'
          AND ui.[client_id] = @ClientId
          AND ui.[data_key] = x.[data_key]
    );
END;

COMMIT TRAN;
