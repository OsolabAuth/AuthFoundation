SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

MERGE [auth].[client_term] AS target
USING (VALUES
    (
        '00000000000000000000000000000000',
        'osolab-auth-terms',
        '1.0',
        N'https://portal.osolab-auth.jp/terms/osolab-auth',
        CAST(1 AS tinyint)
    )
) AS source(client_id, term_id, term_version, term_url, required)
ON target.client_id = source.client_id
    AND target.term_id = source.term_id
WHEN MATCHED THEN
    UPDATE SET
        term_version = source.term_version,
        term_url = source.term_url,
        required = source.required,
        update_datetime = SYSUTCDATETIME(),
        status = 1
WHEN NOT MATCHED THEN
    INSERT (
        client_id,
        term_id,
        term_version,
        term_url,
        required,
        create_datetime,
        update_datetime,
        status
    )
    VALUES (
        source.client_id,
        source.term_id,
        source.term_version,
        source.term_url,
        source.required,
        SYSUTCDATETIME(),
        SYSUTCDATETIME(),
        1
    );
GO
