BEGIN TRAN;

IF OBJECT_ID(N'[auth].[jwk_master]', N'U') IS NULL
BEGIN
    CREATE TABLE [auth].[jwk_master](
        [sequence_id] [bigint] IDENTITY(1,1) NOT NULL,
        [kid] [varchar](64) NOT NULL,
        [kty] [varchar](16) NOT NULL,
        [alg] [varchar](16) NOT NULL,
        [key_use] [varchar](16) NOT NULL,
        [public_n] [varchar](512) NOT NULL,
        [public_e] [varchar](16) NOT NULL,
        [private_key_ciphertext] [varbinary](max) NOT NULL,
        [private_key_iv] [varbinary](12) NOT NULL,
        [private_key_tag] [varbinary](16) NOT NULL,
        [create_datetime] [datetime2](0) NOT NULL,
        [update_datetime] [datetime2](0) NOT NULL,
        [status] [tinyint] NOT NULL,
        CONSTRAINT [PK_jwk_master] PRIMARY KEY CLUSTERED ([sequence_id] ASC)
    ) ON [PRIMARY];
END

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UQ_jwk_master_kid' AND object_id = OBJECT_ID(N'[auth].[jwk_master]'))
BEGIN
    CREATE UNIQUE NONCLUSTERED INDEX [UQ_jwk_master_kid]
    ON [auth].[jwk_master]([kid]);
END

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_jwk_master_status_update_datetime' AND object_id = OBJECT_ID(N'[auth].[jwk_master]'))
BEGIN
    CREATE NONCLUSTERED INDEX [IX_jwk_master_status_update_datetime]
    ON [auth].[jwk_master]([status], [update_datetime]);
END

COMMIT TRAN;
