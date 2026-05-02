SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

BEGIN TRAN;

IF SCHEMA_ID('auth') IS NULL
    EXEC('CREATE SCHEMA [auth]');
GO

IF OBJECT_ID(N'[auth].[client_terms]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[client_terms](
        [term_id] [bigint] IDENTITY(1,1) NOT NULL,
        [client_id] [varchar](32) NOT NULL,
        [term_version] [varchar](32) NOT NULL,
        [term_title] [nvarchar](128) NOT NULL,
        [term_url] [nvarchar](1024) NOT NULL,
        [required] [bit] NOT NULL CONSTRAINT [DF_client_terms_required] DEFAULT ((1)),
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        [status] [tinyint] NOT NULL,
        CONSTRAINT [PK_client_terms] PRIMARY KEY CLUSTERED ([term_id] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[client_scopes]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[client_scopes](
        [sequence_id] [bigint] IDENTITY(1,1) NOT NULL,
        [client_id] [varchar](32) NOT NULL,
        [scope] [varchar](128) NOT NULL,
        [required] [bit] NOT NULL CONSTRAINT [DF_client_scopes_required] DEFAULT ((1)),
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        [status] [tinyint] NOT NULL,
        CONSTRAINT [PK_client_scopes] PRIMARY KEY CLUSTERED ([sequence_id] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[user_terms]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[user_terms](
        [sequence_id] [bigint] IDENTITY(1,1) NOT NULL,
        [osolab_id] [nvarchar](16) NOT NULL,
        [client_id] [varchar](32) NOT NULL,
        [term_id] [bigint] NOT NULL,
        [term_version] [varchar](32) NOT NULL,
        [agreed_at] [datetime2](0) NOT NULL,
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        [status] [tinyint] NOT NULL,
        CONSTRAINT [PK_user_terms] PRIMARY KEY CLUSTERED ([sequence_id] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[user_client_scopes]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[user_client_scopes](
        [sequence_id] [bigint] IDENTITY(1,1) NOT NULL,
        [osolab_id] [nvarchar](16) NOT NULL,
        [client_id] [varchar](32) NOT NULL,
        [scope] [varchar](128) NOT NULL,
        [agreed_at] [datetime2](0) NOT NULL,
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        [status] [tinyint] NOT NULL,
        CONSTRAINT [PK_user_client_scopes] PRIMARY KEY CLUSTERED ([sequence_id] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[FK_client_terms_client_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[client_terms]
        ADD CONSTRAINT [FK_client_terms_client_id]
        FOREIGN KEY([client_id]) REFERENCES [auth].[client_master]([client_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_client_scopes_client_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[client_scopes]
        ADD CONSTRAINT [FK_client_scopes_client_id]
        FOREIGN KEY([client_id]) REFERENCES [auth].[client_master]([client_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_user_terms_osolab_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[user_terms]
        ADD CONSTRAINT [FK_user_terms_osolab_id]
        FOREIGN KEY([osolab_id]) REFERENCES [auth].[osolab_user]([osolab_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_user_terms_client_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[user_terms]
        ADD CONSTRAINT [FK_user_terms_client_id]
        FOREIGN KEY([client_id]) REFERENCES [auth].[client_master]([client_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_user_terms_term_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[user_terms]
        ADD CONSTRAINT [FK_user_terms_term_id]
        FOREIGN KEY([term_id]) REFERENCES [auth].[client_terms]([term_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_user_client_scopes_osolab_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[user_client_scopes]
        ADD CONSTRAINT [FK_user_client_scopes_osolab_id]
        FOREIGN KEY([osolab_id]) REFERENCES [auth].[osolab_user]([osolab_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_user_client_scopes_client_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[user_client_scopes]
        ADD CONSTRAINT [FK_user_client_scopes_client_id]
        FOREIGN KEY([client_id]) REFERENCES [auth].[client_master]([client_id]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UX_client_terms_client_term_version' AND object_id = OBJECT_ID(N'[auth].[client_terms]'))
BEGIN
    CREATE UNIQUE NONCLUSTERED INDEX [UX_client_terms_client_term_version]
    ON [auth].[client_terms]([client_id], [term_version]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UX_client_scopes_client_scope' AND object_id = OBJECT_ID(N'[auth].[client_scopes]'))
BEGIN
    CREATE UNIQUE NONCLUSTERED INDEX [UX_client_scopes_client_scope]
    ON [auth].[client_scopes]([client_id], [scope]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UX_user_terms_osolab_client_term' AND object_id = OBJECT_ID(N'[auth].[user_terms]'))
BEGIN
    CREATE UNIQUE NONCLUSTERED INDEX [UX_user_terms_osolab_client_term]
    ON [auth].[user_terms]([osolab_id], [client_id], [term_id], [term_version]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UX_user_client_scopes_osolab_client_scope' AND object_id = OBJECT_ID(N'[auth].[user_client_scopes]'))
BEGIN
    CREATE UNIQUE NONCLUSTERED INDEX [UX_user_client_scopes_osolab_client_scope]
    ON [auth].[user_client_scopes]([osolab_id], [client_id], [scope]);
END
GO

COMMIT TRAN;
