SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

BEGIN TRAN;

IF SCHEMA_ID('auth') IS NULL
    EXEC('CREATE SCHEMA [auth]');
GO

-- Reset target auth tables before initialization.
DECLARE @dropFkSql nvarchar(max);

;WITH TargetTables AS (
    SELECT OBJECT_ID(N'[auth].[user_info]') AS object_id
    UNION ALL SELECT OBJECT_ID(N'[auth].[user_client_scope_consent]')
    UNION ALL SELECT OBJECT_ID(N'[auth].[user_term_consent]')
    UNION ALL SELECT OBJECT_ID(N'[auth].[client_scope]')
    UNION ALL SELECT OBJECT_ID(N'[auth].[client_redirect_uri]')
    UNION ALL SELECT OBJECT_ID(N'[auth].[client_data_key]')
    UNION ALL SELECT OBJECT_ID(N'[auth].[scope_data_key]')
    UNION ALL SELECT OBJECT_ID(N'[auth].[client_term]')
    UNION ALL SELECT OBJECT_ID(N'[auth].[scope_master]')
    UNION ALL SELECT OBJECT_ID(N'[auth].[data_key_master]')
    UNION ALL SELECT OBJECT_ID(N'[auth].[client_master]')
    UNION ALL SELECT OBJECT_ID(N'[auth].[osolab_user]')
    UNION ALL SELECT OBJECT_ID(N'[auth].[term_master]')
)
SELECT @dropFkSql = STRING_AGG(
    N'ALTER TABLE ' + QUOTENAME(OBJECT_SCHEMA_NAME(fk.parent_object_id))
    + N'.' + QUOTENAME(OBJECT_NAME(fk.parent_object_id))
    + N' DROP CONSTRAINT ' + QUOTENAME(fk.name),
    N';' + CHAR(10))
FROM sys.foreign_keys fk
WHERE fk.parent_object_id IN (SELECT object_id FROM TargetTables WHERE object_id IS NOT NULL)
   OR fk.referenced_object_id IN (SELECT object_id FROM TargetTables WHERE object_id IS NOT NULL);

IF @dropFkSql IS NOT NULL AND LEN(@dropFkSql) > 0
BEGIN
    EXEC sp_executesql @dropFkSql;
END
GO

DROP TABLE IF EXISTS [auth].[user_info];
DROP TABLE IF EXISTS [auth].[user_client_scope_consent];
DROP TABLE IF EXISTS [auth].[user_term_consent];
DROP TABLE IF EXISTS [auth].[client_scope];
DROP TABLE IF EXISTS [auth].[client_redirect_uri];
DROP TABLE IF EXISTS [auth].[client_data_key];
DROP TABLE IF EXISTS [auth].[scope_data_key];
DROP TABLE IF EXISTS [auth].[client_term];
DROP TABLE IF EXISTS [auth].[scope_master];
DROP TABLE IF EXISTS [auth].[data_key_master];
DROP TABLE IF EXISTS [auth].[client_master];
DROP TABLE IF EXISTS [auth].[osolab_user];
DROP TABLE IF EXISTS [auth].[term_master];
GO

IF OBJECT_ID(N'[auth].[client_master]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[client_master](
        [client_id] [varchar](32) NOT NULL,
        [client_name] [nvarchar](64) NOT NULL,
        [client_secret] [varchar](64) NOT NULL,
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        [status] [tinyint] NOT NULL,
        CONSTRAINT [PK_client_master] PRIMARY KEY CLUSTERED ([client_id] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[osolab_user]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[osolab_user](
        [osolab_id] [nvarchar](16) NOT NULL,
        [email] [varchar](255) NOT NULL,
        [password] [varchar](128) NOT NULL,
        [nonce] [varchar](8) NOT NULL,
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        [status] [tinyint] NOT NULL,
        CONSTRAINT [PK_osolab_user] PRIMARY KEY CLUSTERED ([osolab_id] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[user_info]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[user_info](
        [osolab_id] [nvarchar](16) NOT NULL,
        [client_id] [varchar](32) NOT NULL,
        [data_key] [varchar](64) NOT NULL,
        [data_value] [nvarchar](4000) NOT NULL,
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        [status] [tinyint] NOT NULL,
        CONSTRAINT [PK_user_info] PRIMARY KEY CLUSTERED ([osolab_id] ASC, [client_id] ASC, [data_key] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[data_key_master]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[data_key_master](
        [data_key] [varchar](64) NOT NULL,
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        CONSTRAINT [PK_data_key_master] PRIMARY KEY CLUSTERED ([data_key] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[client_data_key]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[client_data_key](
        [sequence_id] [bigint] IDENTITY(1,1) NOT NULL,
        [client_id] [varchar](32) NOT NULL,
        [data_key] [varchar](64) NOT NULL,
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        [status] [tinyint] NOT NULL,
        CONSTRAINT [PK_client_data_key] PRIMARY KEY CLUSTERED ([sequence_id] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[client_redirect_uri]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[client_redirect_uri](
        [sequence_id] [bigint] IDENTITY(1,1) NOT NULL,
        [client_id] [varchar](32) NOT NULL,
        [redirect_uri] [nvarchar](2048) NOT NULL,
        [is_default] [tinyint] NOT NULL CONSTRAINT [DF_client_redirect_uri_is_default] DEFAULT ((0)),
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        [status] [tinyint] NOT NULL,
        CONSTRAINT [PK_client_redirect_uri] PRIMARY KEY CLUSTERED ([sequence_id] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[scope_master]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[scope_master](
        [scope] [varchar](64) NOT NULL,
        [description] [nvarchar](255) NOT NULL,
        [confidential_only] [tinyint] NOT NULL CONSTRAINT [DF_scope_master_confidential_only] DEFAULT ((0)),
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        [status] [tinyint] NOT NULL,
        CONSTRAINT [PK_scope_master] PRIMARY KEY CLUSTERED ([scope] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[client_scope]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[client_scope](
        [sequence_id] [bigint] IDENTITY(1,1) NOT NULL,
        [client_id] [varchar](32) NOT NULL,
        [scope] [varchar](64) NOT NULL,
        [required] [tinyint] NOT NULL CONSTRAINT [DF_client_scope_required] DEFAULT ((1)),
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        [status] [tinyint] NOT NULL,
        CONSTRAINT [PK_client_scope] PRIMARY KEY CLUSTERED ([sequence_id] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[scope_data_key]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[scope_data_key](
        [sequence_id] [bigint] IDENTITY(1,1) NOT NULL,
        [scope] [varchar](64) NOT NULL,
        [data_key] [varchar](64) NOT NULL,
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        [status] [tinyint] NOT NULL,
        CONSTRAINT [PK_scope_data_key] PRIMARY KEY CLUSTERED ([sequence_id] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[client_term]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[client_term](
        [sequence_id] [bigint] IDENTITY(1,1) NOT NULL,
        [client_id] [varchar](32) NOT NULL,
        [term_id] [varchar](64) NOT NULL,
        [term_version] [varchar](32) NOT NULL,
        [term_url] [nvarchar](2048) NOT NULL,
        [required] [tinyint] NOT NULL CONSTRAINT [DF_client_term_required] DEFAULT ((1)),
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        [status] [tinyint] NOT NULL,
        CONSTRAINT [PK_client_term] PRIMARY KEY CLUSTERED ([sequence_id] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[user_term_consent]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[user_term_consent](
        [sequence_id] [bigint] IDENTITY(1,1) NOT NULL,
        [osolab_id] [nvarchar](16) NOT NULL,
        [client_id] [varchar](32) NOT NULL,
        [term_id] [varchar](64) NOT NULL,
        [term_version] [varchar](32) NOT NULL,
        [consent_result] [tinyint] NOT NULL,
        [consented_datetime] [datetime2](0) NOT NULL,
        [create_datetime] [datetime2](0) NOT NULL,
        CONSTRAINT [PK_user_term_consent] PRIMARY KEY CLUSTERED ([sequence_id] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[user_client_scope_consent]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[user_client_scope_consent](
        [sequence_id] [bigint] IDENTITY(1,1) NOT NULL,
        [osolab_id] [nvarchar](16) NOT NULL,
        [client_id] [varchar](32) NOT NULL,
        [scope] [varchar](64) NOT NULL,
        [consented_datetime] [datetime2](0) NOT NULL,
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        [status] [tinyint] NOT NULL,
        CONSTRAINT [PK_user_client_scope_consent] PRIMARY KEY CLUSTERED ([sequence_id] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[FK_user_info_osolab_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[user_info]
        ADD CONSTRAINT [FK_user_info_osolab_id]
        FOREIGN KEY([osolab_id]) REFERENCES [auth].[osolab_user]([osolab_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_user_info_client_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[user_info]
        ADD CONSTRAINT [FK_user_info_client_id]
        FOREIGN KEY([client_id]) REFERENCES [auth].[client_master]([client_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_client_data_key_client_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[client_data_key]
        ADD CONSTRAINT [FK_client_data_key_client_id]
        FOREIGN KEY([client_id]) REFERENCES [auth].[client_master]([client_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_client_data_key_data_key]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[client_data_key]
        ADD CONSTRAINT [FK_client_data_key_data_key]
        FOREIGN KEY([data_key]) REFERENCES [auth].[data_key_master]([data_key]);
END
GO

IF OBJECT_ID(N'[auth].[FK_client_redirect_uri_client_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[client_redirect_uri]
        ADD CONSTRAINT [FK_client_redirect_uri_client_id]
        FOREIGN KEY([client_id]) REFERENCES [auth].[client_master]([client_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_client_scope_client_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[client_scope]
        ADD CONSTRAINT [FK_client_scope_client_id]
        FOREIGN KEY([client_id]) REFERENCES [auth].[client_master]([client_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_client_scope_scope]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[client_scope]
        ADD CONSTRAINT [FK_client_scope_scope]
        FOREIGN KEY([scope]) REFERENCES [auth].[scope_master]([scope]);
END
GO

IF OBJECT_ID(N'[auth].[FK_scope_data_key_scope]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[scope_data_key]
        ADD CONSTRAINT [FK_scope_data_key_scope]
        FOREIGN KEY([scope]) REFERENCES [auth].[scope_master]([scope]);
END
GO

IF OBJECT_ID(N'[auth].[FK_scope_data_key_data_key]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[scope_data_key]
        ADD CONSTRAINT [FK_scope_data_key_data_key]
        FOREIGN KEY([data_key]) REFERENCES [auth].[data_key_master]([data_key]);
END
GO

IF OBJECT_ID(N'[auth].[FK_client_term_client_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[client_term]
        ADD CONSTRAINT [FK_client_term_client_id]
        FOREIGN KEY([client_id]) REFERENCES [auth].[client_master]([client_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_user_term_consent_osolab_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[user_term_consent]
        ADD CONSTRAINT [FK_user_term_consent_osolab_id]
        FOREIGN KEY([osolab_id]) REFERENCES [auth].[osolab_user]([osolab_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_user_term_consent_client_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[user_term_consent]
        ADD CONSTRAINT [FK_user_term_consent_client_id]
        FOREIGN KEY([client_id]) REFERENCES [auth].[client_master]([client_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_user_client_scope_consent_osolab_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[user_client_scope_consent]
        ADD CONSTRAINT [FK_user_client_scope_consent_osolab_id]
        FOREIGN KEY([osolab_id]) REFERENCES [auth].[osolab_user]([osolab_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_user_client_scope_consent_client_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[user_client_scope_consent]
        ADD CONSTRAINT [FK_user_client_scope_consent_client_id]
        FOREIGN KEY([client_id]) REFERENCES [auth].[client_master]([client_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_user_client_scope_consent_scope]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[user_client_scope_consent]
        ADD CONSTRAINT [FK_user_client_scope_consent_scope]
        FOREIGN KEY([scope]) REFERENCES [auth].[scope_master]([scope]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_osolab_user_email' AND object_id = OBJECT_ID(N'[auth].[osolab_user]'))
BEGIN
    CREATE NONCLUSTERED INDEX [IX_osolab_user_email] ON [auth].[osolab_user]([email] ASC);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_user_info_osolab_id_client_id_data_key_status' AND object_id = OBJECT_ID(N'[auth].[user_info]'))
BEGIN
    CREATE NONCLUSTERED INDEX [IX_user_info_osolab_id_client_id_data_key_status]
    ON [auth].[user_info]([osolab_id] ASC, [client_id] ASC, [data_key] ASC, [status] ASC);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_user_info_osolab_id_client_id_status' AND object_id = OBJECT_ID(N'[auth].[user_info]'))
BEGIN
    CREATE NONCLUSTERED INDEX [IX_user_info_osolab_id_client_id_status]
    ON [auth].[user_info]([osolab_id] ASC, [client_id] ASC, [status] ASC);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_user_info_osolab_id_status' AND object_id = OBJECT_ID(N'[auth].[user_info]'))
BEGIN
    CREATE NONCLUSTERED INDEX [IX_user_info_osolab_id_status]
    ON [auth].[user_info]([osolab_id] ASC, [status] ASC);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UQ_client_data_key_client_id_data_key' AND object_id = OBJECT_ID(N'[auth].[client_data_key]'))
BEGIN
    CREATE UNIQUE NONCLUSTERED INDEX [UQ_client_data_key_client_id_data_key]
    ON [auth].[client_data_key]([client_id], [data_key]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UQ_client_redirect_uri_client_id_redirect_uri' AND object_id = OBJECT_ID(N'[auth].[client_redirect_uri]'))
BEGIN
    CREATE UNIQUE NONCLUSTERED INDEX [UQ_client_redirect_uri_client_id_redirect_uri]
    ON [auth].[client_redirect_uri]([client_id], [redirect_uri]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_client_redirect_uri_client_id_status' AND object_id = OBJECT_ID(N'[auth].[client_redirect_uri]'))
BEGIN
    CREATE NONCLUSTERED INDEX [IX_client_redirect_uri_client_id_status]
    ON [auth].[client_redirect_uri]([client_id], [status]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_client_redirect_uri_client_id_redirect_uri_status' AND object_id = OBJECT_ID(N'[auth].[client_redirect_uri]'))
BEGIN
    CREATE NONCLUSTERED INDEX [IX_client_redirect_uri_client_id_redirect_uri_status]
    ON [auth].[client_redirect_uri]([client_id], [redirect_uri], [status]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UQ_client_scope_client_id_scope' AND object_id = OBJECT_ID(N'[auth].[client_scope]'))
BEGIN
    CREATE UNIQUE NONCLUSTERED INDEX [UQ_client_scope_client_id_scope]
    ON [auth].[client_scope]([client_id], [scope]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UQ_scope_data_key_scope_data_key' AND object_id = OBJECT_ID(N'[auth].[scope_data_key]'))
BEGIN
    CREATE UNIQUE NONCLUSTERED INDEX [UQ_scope_data_key_scope_data_key]
    ON [auth].[scope_data_key]([scope], [data_key]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UQ_client_term_client_id_term_id' AND object_id = OBJECT_ID(N'[auth].[client_term]'))
BEGIN
    CREATE UNIQUE NONCLUSTERED INDEX [UQ_client_term_client_id_term_id]
    ON [auth].[client_term]([client_id], [term_id]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_user_term_consent_osolab_id_client_id_term_id_consented_datetime' AND object_id = OBJECT_ID(N'[auth].[user_term_consent]'))
BEGIN
    CREATE NONCLUSTERED INDEX [IX_user_term_consent_osolab_id_client_id_term_id_consented_datetime]
    ON [auth].[user_term_consent]([osolab_id], [client_id], [term_id], [consented_datetime]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UQ_user_client_scope_consent_osolab_id_client_id_scope' AND object_id = OBJECT_ID(N'[auth].[user_client_scope_consent]'))
BEGIN
    CREATE UNIQUE NONCLUSTERED INDEX [UQ_user_client_scope_consent_osolab_id_client_id_scope]
    ON [auth].[user_client_scope_consent]([osolab_id], [client_id], [scope]);
END
GO

COMMIT TRAN;
