IF DB_ID(N'AuthFoundation') IS NULL
BEGIN
    CREATE DATABASE [AuthFoundation];
END;
GO

USE [AuthFoundation];
GO

IF SCHEMA_ID(N'auth') IS NULL
BEGIN
    EXEC(N'CREATE SCHEMA [auth]');
END;
GO

IF OBJECT_ID(N'[auth].[osolab_user]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[osolab_user] (
        [osolab_id] nvarchar(16) NOT NULL,
        [email] nvarchar(320) NOT NULL,
        [password] nvarchar(max) NOT NULL,
        [nonce] nvarchar(64) NOT NULL,
        [create_datetime] datetime2 NOT NULL CONSTRAINT [DF_osolab_user_create_datetime] DEFAULT SYSUTCDATETIME(),
        [update_datetime] datetime2 NOT NULL CONSTRAINT [DF_osolab_user_update_datetime] DEFAULT SYSUTCDATETIME(),
        [status] int NOT NULL CONSTRAINT [DF_osolab_user_status] DEFAULT 1,
        CONSTRAINT [PK_osolab_user] PRIMARY KEY ([osolab_id])
    );

    CREATE UNIQUE INDEX [UX_osolab_user_email_active]
        ON [auth].[osolab_user]([email])
        WHERE [status] = 1;
END;
GO

IF OBJECT_ID(N'[auth].[user_info]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[user_info] (
        [osolab_id] nvarchar(16) NOT NULL,
        [client_id] nvarchar(32) NOT NULL,
        [data_key] nvarchar(100) NOT NULL,
        [data_value] nvarchar(max) NOT NULL,
        [create_datetime] datetime2 NOT NULL CONSTRAINT [DF_user_info_create_datetime] DEFAULT SYSUTCDATETIME(),
        [update_datetime] datetime2 NOT NULL CONSTRAINT [DF_user_info_update_datetime] DEFAULT SYSUTCDATETIME(),
        [status] int NOT NULL CONSTRAINT [DF_user_info_status] DEFAULT 1,
        CONSTRAINT [PK_user_info] PRIMARY KEY ([osolab_id], [client_id], [data_key])
    );
END;
GO

IF OBJECT_ID(N'[auth].[term_master]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[term_master] (
        [term_id] nvarchar(100) NOT NULL,
        [term_type] nvarchar(50) NOT NULL,
        [title] nvarchar(200) NOT NULL,
        [version] nvarchar(50) NOT NULL,
        [content] nvarchar(max) NOT NULL,
        [effective_start_datetime] datetime2 NOT NULL,
        [effective_end_datetime] datetime2 NULL,
        [create_datetime] datetime2 NOT NULL CONSTRAINT [DF_term_master_create_datetime] DEFAULT SYSUTCDATETIME(),
        [update_datetime] datetime2 NOT NULL CONSTRAINT [DF_term_master_update_datetime] DEFAULT SYSUTCDATETIME(),
        [status] int NOT NULL CONSTRAINT [DF_term_master_status] DEFAULT 1,
        CONSTRAINT [PK_term_master] PRIMARY KEY ([term_id])
    );
END;
GO

IF OBJECT_ID(N'[auth].[client_term]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[client_term] (
        [client_id] nvarchar(32) NOT NULL,
        [term_id] nvarchar(100) NOT NULL,
        [required] bit NOT NULL,
        [display_order] int NOT NULL,
        [create_datetime] datetime2 NOT NULL CONSTRAINT [DF_client_term_create_datetime] DEFAULT SYSUTCDATETIME(),
        [update_datetime] datetime2 NOT NULL CONSTRAINT [DF_client_term_update_datetime] DEFAULT SYSUTCDATETIME(),
        [status] int NOT NULL CONSTRAINT [DF_client_term_status] DEFAULT 1,
        CONSTRAINT [PK_client_term] PRIMARY KEY ([client_id], [term_id])
    );
END;
GO

IF OBJECT_ID(N'[auth].[user_term_consent]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[user_term_consent] (
        [consent_id] bigint IDENTITY(1,1) NOT NULL,
        [osolab_id] nvarchar(16) NOT NULL,
        [client_id] nvarchar(32) NOT NULL,
        [term_id] nvarchar(100) NOT NULL,
        [term_version] nvarchar(50) NOT NULL,
        [consent_result] bit NOT NULL,
        [consented_datetime] datetime2 NOT NULL,
        [create_datetime] datetime2 NOT NULL CONSTRAINT [DF_user_term_consent_create_datetime] DEFAULT SYSUTCDATETIME(),
        CONSTRAINT [PK_user_term_consent] PRIMARY KEY ([consent_id])
    );
END;
GO

IF OBJECT_ID(N'[auth].[agent]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[agent] (
        [agent_id] nvarchar(64) NOT NULL,
        [owner_osolab_id] nvarchar(16) NOT NULL,
        [agent_name] nvarchar(100) NOT NULL,
        [secret_hash] nvarchar(max) NOT NULL,
        [status] nvarchar(20) NOT NULL CONSTRAINT [DF_agent_status] DEFAULT N'active',
        [revoked_datetime] datetime2 NULL,
        [create_datetime] datetime2 NOT NULL CONSTRAINT [DF_agent_create_datetime] DEFAULT SYSUTCDATETIME(),
        [update_datetime] datetime2 NOT NULL CONSTRAINT [DF_agent_update_datetime] DEFAULT SYSUTCDATETIME(),
        CONSTRAINT [PK_agent] PRIMARY KEY ([agent_id])
    );

    CREATE INDEX [IX_agent_owner_active]
        ON [auth].[agent]([owner_osolab_id], [status]);
END;
GO

IF OBJECT_ID(N'[auth].[agent_delegation]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[agent_delegation] (
        [delegation_id] nvarchar(64) NOT NULL,
        [agent_id] nvarchar(64) NOT NULL,
        [owner_osolab_id] nvarchar(16) NOT NULL,
        [client_id] nvarchar(32) NOT NULL,
        [scope] nvarchar(500) NOT NULL,
        [expires_datetime] datetime2 NOT NULL,
        [create_datetime] datetime2 NOT NULL CONSTRAINT [DF_agent_delegation_create_datetime] DEFAULT SYSUTCDATETIME(),
        [status] int NOT NULL CONSTRAINT [DF_agent_delegation_status] DEFAULT 1,
        CONSTRAINT [PK_agent_delegation] PRIMARY KEY ([delegation_id])
    );

    CREATE INDEX [IX_agent_delegation_token_lookup]
        ON [auth].[agent_delegation]([agent_id], [client_id], [status], [expires_datetime]);
END;
GO
