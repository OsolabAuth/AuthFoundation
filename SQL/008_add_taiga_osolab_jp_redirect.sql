SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

MERGE [auth].[client_redirect_uri] AS target
USING (VALUES
    ('30000000000000000000000000000001', N'https://taiga.osolab.jp/oidc/callback/', 0)
) AS source(client_id, redirect_uri, is_default)
ON target.client_id = source.client_id AND target.redirect_uri = source.redirect_uri
WHEN MATCHED THEN UPDATE SET
    is_default = source.is_default,
    update_datetime = SYSUTCDATETIME(),
    status = 1
WHEN NOT MATCHED THEN INSERT(client_id, redirect_uri, is_default, create_datetime, update_datetime, status)
    VALUES(source.client_id, source.redirect_uri, source.is_default, SYSUTCDATETIME(), SYSUTCDATETIME(), 1);
GO
