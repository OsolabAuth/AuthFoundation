SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

-- consolidated final table DDL generated from all *__up.sql
IF SCHEMA_ID('auth') IS NULL
    EXEC('CREATE SCHEMA [auth]');
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
     CONSTRAINT [PK_client_master] PRIMARY KEY CLUSTERED 
    (
    	[client_id] ASC
    )WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF) ON [PRIMARY]
    ) ON [PRIMARY]
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
     CONSTRAINT [PK_osolab_user] PRIMARY KEY CLUSTERED 
    (
    	[osolab_id] ASC
    )WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF) ON [PRIMARY]
    ) ON [PRIMARY]
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
     CONSTRAINT [PK_user_info] PRIMARY KEY CLUSTERED 
    (
    	[osolab_id] ASC,
    	[client_id] ASC,
    	[data_key] ASC
    )WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF) ON [PRIMARY]
    ) ON [PRIMARY]
END
GO

ALTER TABLE [auth].[user_info]  
	ADD CONSTRAINT [FK_user_info_osolab_id] FOREIGN KEY([osolab_id])
		REFERENCES [auth].[osolab_user] ([osolab_id])

ALTER TABLE [auth].[user_info]  
	ADD CONSTRAINT [FK_user_info_client_id] FOREIGN KEY([client_id])
		REFERENCES [auth].[client_master] ([client_id])



IF OBJECT_ID(N'[auth].[data_key_master]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[data_key_master](
    	[data_key] [varchar](64) NOT NULL,
    	[create_datetime] [datetime2](0) NOT NULL,
    	[update_datetime] [datetime2](0) NOT NULL,
     CONSTRAINT [PK_data_key_master] PRIMARY KEY CLUSTERED 
    (
    	[data_key] ASC
    )WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF) ON [PRIMARY]
    ) ON [PRIMARY]
END
GO

IF OBJECT_ID(N'[auth].[client_data_key]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[client_data_key](
        [sequence_id] [bigint] IDENTITY(1,1) NOT NULL ,
    	[client_id] [varchar](32) NOT NULL,
    	[data_key] [varchar](64) NOT NULL,
    	[create_datetime] [datetime2](0) NOT NULL,
    	[update_datetime] [datetime2](0) NOT NULL,
     CONSTRAINT [PK_client_data_key] PRIMARY KEY CLUSTERED 
    (
    	[sequence_id] ASC
    )WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF) ON [PRIMARY]
    ) ON [PRIMARY]
END
GO

ALTER TABLE [auth].[client_data_key]  
	ADD CONSTRAINT [FK_client_data_key_client_id] FOREIGN KEY([client_id])
		REFERENCES [auth].[client_master] ([client_id])

ALTER TABLE [auth].[client_data_key]  
	ADD CONSTRAINT [FK_client_data_key_data_key] FOREIGN KEY([data_key])
		REFERENCES [auth].[data_key_master] ([data_key])


CREATE NONCLUSTERED INDEX [IX_osolab_user_email] ON [auth].[osolab_user]
(
	[email] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, DROP_EXISTING = OFF, ONLINE = OFF) ON [PRIMARY]
GO

CREATE NONCLUSTERED INDEX [IX_user_info_osolab_id_client_id_data_key_status] ON [auth].[user_info]
(
	[osolab_id] ASC,
	[client_id] ASC,
	[data_key] ASC,
	[status] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, DROP_EXISTING = OFF, ONLINE = OFF) ON [PRIMARY]
GO

CREATE NONCLUSTERED INDEX [IX_user_info_osolab_id_client_id_status] ON [auth].[user_info]
(
	[osolab_id] ASC,
	[client_id] ASC,
	[status] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, DROP_EXISTING = OFF, ONLINE = OFF) ON [PRIMARY]
GO

CREATE NONCLUSTERED INDEX [IX_user_info_osolab_id_status] ON [auth].[user_info]
(
	[osolab_id] ASC,
	[status] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, DROP_EXISTING = OFF, ONLINE = OFF) ON [PRIMARY]
GO
