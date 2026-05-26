SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

DECLARE @now datetime2(3) = SYSUTCDATETIME();

MERGE [auth].[client_master] AS target
USING (VALUES
    ('20000000000000000000000000000001', N'Portfolio Profile Site', '0000000000000000000000000000000000000000000000000000000000000001'),
    ('20000000000000000000000000000002', N'Portfolio Docs Site', '0000000000000000000000000000000000000000000000000000000000000002'),
    ('30000000000000000000000000000001', N'Taiga Portfolio', '3333333333333333333333333333333333333333333333333333333333333333')
) AS source(client_id, client_name, client_secret)
ON target.client_id = source.client_id
WHEN MATCHED THEN UPDATE SET
    client_name = source.client_name,
    update_datetime = @now,
    status = 1
WHEN NOT MATCHED THEN INSERT(client_id, client_name, client_secret, create_datetime, update_datetime, status)
    VALUES(source.client_id, source.client_name, source.client_secret, @now, @now, 1);
GO

MERGE [auth].[client_redirect_uri] AS target
USING (VALUES
    ('20000000000000000000000000000001', N'http://localhost:5800/auth/callback', 0),
    ('20000000000000000000000000000001', N'https://portfolio-profile-site-210279746180.us-west1.run.app/auth/callback', 1),
    ('20000000000000000000000000000002', N'http://localhost:5900/auth/callback', 0),
    ('20000000000000000000000000000002', N'https://portfolio-docs-site-210279746180.us-west1.run.app/auth/callback', 1),
    ('30000000000000000000000000000001', N'http://localhost:9000/oidc/callback/', 1),
    ('30000000000000000000000000000001', N'http://100.125.117.124:9000/oidc/callback/', 0),
    ('30000000000000000000000000000001', N'https://home.tail8478bf.ts.net/oidc/callback/', 0),
    ('30000000000000000000000000000001', N'https://ready-florist-concerning-mins.trycloudflare.com/oidc/callback/', 0),
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

MERGE [auth].[client_scope] AS target
USING (VALUES
    ('20000000000000000000000000000001', 'openid', 1),
    ('20000000000000000000000000000001', 'profile', 0),
    ('20000000000000000000000000000001', 'email', 0),
    ('20000000000000000000000000000002', 'openid', 1),
    ('20000000000000000000000000000002', 'profile', 0),
    ('20000000000000000000000000000002', 'email', 0),
    ('30000000000000000000000000000001', 'openid', 1),
    ('30000000000000000000000000000001', 'profile', 0),
    ('30000000000000000000000000000001', 'email', 0)
) AS source(client_id, scope, required)
ON target.client_id = source.client_id AND target.scope = source.scope
WHEN MATCHED THEN UPDATE SET
    required = source.required,
    update_datetime = SYSUTCDATETIME(),
    status = 1
WHEN NOT MATCHED THEN INSERT(client_id, scope, required, create_datetime, update_datetime, status)
    VALUES(source.client_id, source.scope, source.required, SYSUTCDATETIME(), SYSUTCDATETIME(), 1);
GO

MERGE [auth].[client_data_key] AS target
USING (VALUES
    ('20000000000000000000000000000001', 'sub'),
    ('20000000000000000000000000000001', 'email'),
    ('20000000000000000000000000000001', 'name'),
    ('20000000000000000000000000000001', 'preferred_username'),
    ('20000000000000000000000000000001', 'email_verified'),
    ('20000000000000000000000000000001', 'birthdate'),
    ('20000000000000000000000000000002', 'sub'),
    ('20000000000000000000000000000002', 'email'),
    ('20000000000000000000000000000002', 'name'),
    ('20000000000000000000000000000002', 'preferred_username'),
    ('20000000000000000000000000000002', 'email_verified'),
    ('20000000000000000000000000000002', 'birthdate'),
    ('30000000000000000000000000000001', 'sub'),
    ('30000000000000000000000000000001', 'email'),
    ('30000000000000000000000000000001', 'name'),
    ('30000000000000000000000000000001', 'preferred_username'),
    ('30000000000000000000000000000001', 'email_verified'),
    ('30000000000000000000000000000001', 'birthdate')
) AS source(client_id, data_key)
ON target.client_id = source.client_id AND target.data_key = source.data_key
WHEN MATCHED THEN UPDATE SET
    update_datetime = SYSUTCDATETIME(),
    status = 1
WHEN NOT MATCHED THEN INSERT(client_id, data_key, create_datetime, update_datetime, status)
    VALUES(source.client_id, source.data_key, SYSUTCDATETIME(), SYSUTCDATETIME(), 1);
GO
