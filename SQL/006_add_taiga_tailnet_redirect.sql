SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

MERGE [auth].[client_redirect_uri] AS target
USING (VALUES
    ('30000000000000000000000000000001', N'http://100.125.117.124:9000/oidc/callback/', 0),
    ('30000000000000000000000000000001', N'https://home.tail8478bf.ts.net/oidc/callback/', 0)
) AS source(client_id, redirect_uri, is_default)
ON target.client_id = source.client_id AND target.redirect_uri = source.redirect_uri
WHEN MATCHED THEN UPDATE SET
    is_default = source.is_default,
    update_datetime = SYSUTCDATETIME(),
    status = 1
WHEN NOT MATCHED THEN INSERT(client_id, redirect_uri, is_default, create_datetime, update_datetime, status)
    VALUES(source.client_id, source.redirect_uri, source.is_default, SYSUTCDATETIME(), SYSUTCDATETIME(), 1);
GO
