BEGIN TRAN;

IF NOT EXISTS (
    SELECT 1
    FROM [auth].[client_redirect_uri]
    WHERE [client_id] = '00000000000000000000000000000000'
      AND [redirect_uri] = N'https://portal.osolab-auth.jp/'
)
BEGIN
    INSERT INTO [auth].[client_redirect_uri](
        [client_id],
        [redirect_uri],
        [is_default],
        [create_datetime],
        [update_datetime],
        [status]
    )
    VALUES (
        '00000000000000000000000000000000',
        N'https://portal.osolab-auth.jp/',
        1,
        SYSDATETIME(),
        SYSDATETIME(),
        1
    );
END

COMMIT TRAN;
