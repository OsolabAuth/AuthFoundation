SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

DECLARE @now datetime2(3) = SYSUTCDATETIME();

MERGE [auth].[data_key_master] AS target
USING (VALUES
    ('birthdate')
) AS source(data_key)
ON target.data_key = source.data_key
WHEN NOT MATCHED THEN INSERT(data_key, create_datetime, update_datetime)
    VALUES(source.data_key, @now, @now);
GO

MERGE [auth].[client_data_key] AS target
USING (VALUES
    ('00000000000000000000000000000000', 'birthdate'),
    ('20000000000000000000000000000001', 'birthdate'),
    ('20000000000000000000000000000002', 'birthdate'),
    ('30000000000000000000000000000001', 'birthdate')
) AS source(client_id, data_key)
ON target.client_id = source.client_id AND target.data_key = source.data_key
WHEN MATCHED THEN UPDATE SET
    update_datetime = SYSUTCDATETIME(),
    status = 1
WHEN NOT MATCHED THEN INSERT(client_id, data_key, create_datetime, update_datetime, status)
    VALUES(source.client_id, source.data_key, SYSUTCDATETIME(), SYSUTCDATETIME(), 1);
GO

MERGE [auth].[scope_data_key] AS target
USING (VALUES
    ('profile', 'birthdate')
) AS source(scope, data_key)
ON target.scope = source.scope AND target.data_key = source.data_key
WHEN MATCHED THEN UPDATE SET
    update_datetime = SYSUTCDATETIME(),
    status = 1
WHEN NOT MATCHED THEN INSERT(scope, data_key, create_datetime, update_datetime, status)
    VALUES(source.scope, source.data_key, SYSUTCDATETIME(), SYSUTCDATETIME(), 1);
GO
