SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

IF OBJECT_ID(N'[auth].[agent_master]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[agent_master](
        [agent_id] [varchar](64) NOT NULL,
        [owner_osolab_id] [nvarchar](16) NOT NULL,
        [agent_name] [nvarchar](128) NOT NULL,
        [secret_hash] [varchar](128) NOT NULL,
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        [last_used_datetime] [datetime2](0) NULL,
        [revoked_datetime] [datetime2](0) NULL,
        [status] [tinyint] NOT NULL,
        CONSTRAINT [PK_agent_master] PRIMARY KEY CLUSTERED ([agent_id] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[agent_delegation]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[agent_delegation](
        [delegation_id] [varchar](64) NOT NULL,
        [agent_id] [varchar](64) NOT NULL,
        [owner_osolab_id] [nvarchar](16) NOT NULL,
        [client_id] [varchar](32) NOT NULL,
        [scopes] [varchar](1000) NOT NULL,
        [expires_datetime] [datetime2](0) NOT NULL,
        [verified_datetime] [datetime2](0) NULL,
        [revoked_datetime] [datetime2](0) NULL,
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        [status] [tinyint] NOT NULL,
        CONSTRAINT [PK_agent_delegation] PRIMARY KEY CLUSTERED ([delegation_id] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[agent_audit_log]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[agent_audit_log](
        [audit_log_id] [bigint] IDENTITY(1,1) NOT NULL,
        [agent_id] [varchar](64) NULL,
        [owner_osolab_id] [nvarchar](16) NULL,
        [delegation_id] [varchar](64) NULL,
        [event_type] [varchar](64) NOT NULL,
        [client_id] [varchar](32) NULL,
        [scope] [varchar](1000) NULL,
        [resource] [nvarchar](255) NULL,
        [result] [varchar](32) NOT NULL,
        [ip_address] [nvarchar](64) NULL,
        [user_agent] [nvarchar](512) NULL,
        [create_datetime] [datetime2](0) NOT NULL,
        CONSTRAINT [PK_agent_audit_log] PRIMARY KEY CLUSTERED ([audit_log_id] ASC)
    ) ON [PRIMARY];
END
GO

IF OBJECT_ID(N'[auth].[FK_agent_master_owner_osolab_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[agent_master]
        ADD CONSTRAINT [FK_agent_master_owner_osolab_id]
        FOREIGN KEY([owner_osolab_id]) REFERENCES [auth].[osolab_user]([osolab_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_agent_delegation_agent_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[agent_delegation]
        ADD CONSTRAINT [FK_agent_delegation_agent_id]
        FOREIGN KEY([agent_id]) REFERENCES [auth].[agent_master]([agent_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_agent_delegation_owner_osolab_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[agent_delegation]
        ADD CONSTRAINT [FK_agent_delegation_owner_osolab_id]
        FOREIGN KEY([owner_osolab_id]) REFERENCES [auth].[osolab_user]([osolab_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_agent_delegation_client_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[agent_delegation]
        ADD CONSTRAINT [FK_agent_delegation_client_id]
        FOREIGN KEY([client_id]) REFERENCES [auth].[client_master]([client_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_agent_audit_log_agent_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[agent_audit_log]
        ADD CONSTRAINT [FK_agent_audit_log_agent_id]
        FOREIGN KEY([agent_id]) REFERENCES [auth].[agent_master]([agent_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_agent_audit_log_owner_osolab_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[agent_audit_log]
        ADD CONSTRAINT [FK_agent_audit_log_owner_osolab_id]
        FOREIGN KEY([owner_osolab_id]) REFERENCES [auth].[osolab_user]([osolab_id]);
END
GO

IF OBJECT_ID(N'[auth].[FK_agent_audit_log_delegation_id]', N'F') IS NULL
BEGIN
    ALTER TABLE [auth].[agent_audit_log]
        ADD CONSTRAINT [FK_agent_audit_log_delegation_id]
        FOREIGN KEY([delegation_id]) REFERENCES [auth].[agent_delegation]([delegation_id]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_agent_master_owner_osolab_id_status' AND object_id = OBJECT_ID(N'[auth].[agent_master]'))
BEGIN
    CREATE NONCLUSTERED INDEX [IX_agent_master_owner_osolab_id_status]
    ON [auth].[agent_master]([owner_osolab_id], [status]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_agent_delegation_agent_id_client_id_status' AND object_id = OBJECT_ID(N'[auth].[agent_delegation]'))
BEGIN
    CREATE NONCLUSTERED INDEX [IX_agent_delegation_agent_id_client_id_status]
    ON [auth].[agent_delegation]([agent_id], [client_id], [status]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_agent_delegation_owner_osolab_id_status' AND object_id = OBJECT_ID(N'[auth].[agent_delegation]'))
BEGIN
    CREATE NONCLUSTERED INDEX [IX_agent_delegation_owner_osolab_id_status]
    ON [auth].[agent_delegation]([owner_osolab_id], [status]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_agent_audit_log_agent_id_create_datetime' AND object_id = OBJECT_ID(N'[auth].[agent_audit_log]'))
BEGIN
    CREATE NONCLUSTERED INDEX [IX_agent_audit_log_agent_id_create_datetime]
    ON [auth].[agent_audit_log]([agent_id], [create_datetime]);
END
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_agent_audit_log_owner_osolab_id_create_datetime' AND object_id = OBJECT_ID(N'[auth].[agent_audit_log]'))
BEGIN
    CREATE NONCLUSTERED INDEX [IX_agent_audit_log_owner_osolab_id_create_datetime]
    ON [auth].[agent_audit_log]([owner_osolab_id], [create_datetime]);
END
GO
