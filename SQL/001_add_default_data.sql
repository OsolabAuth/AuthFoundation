BEGIN TRAN;

INSERT INTO [auth].[client_master] ([client_id],[client_name],[client_secret],[create_datetime],[update_datetime],[status])
VALUES
('00000000000000000000000000000000','OsolabAuth','0000000000000000', SYSDATETIME(), SYSDATETIME(),'1');

INSERT INTO [auth].[data_key_master]([data_key],[create_datetime],[update_datetime])
VALUES
('sub', SYSDATETIME(), SYSDATETIME()),
('email', SYSDATETIME(), SYSDATETIME()),
('name', SYSDATETIME(), SYSDATETIME()),
('preferred_username', SYSDATETIME(), SYSDATETIME()),
('birthdate', SYSDATETIME(), SYSDATETIME()),
('latest_login_datetime', SYSDATETIME(), SYSDATETIME()),
('email_verified', SYSDATETIME(), SYSDATETIME());

INSERT INTO [auth].[client_data_key]([client_id],[data_key],[create_datetime],[update_datetime],[status])
VALUES
('00000000000000000000000000000000','sub', SYSDATETIME(), SYSDATETIME(),'1'),
('00000000000000000000000000000000','email', SYSDATETIME(), SYSDATETIME(),'1'),
('00000000000000000000000000000000','name', SYSDATETIME(), SYSDATETIME(),'1'),
('00000000000000000000000000000000','preferred_username', SYSDATETIME(), SYSDATETIME(),'1'),
('00000000000000000000000000000000','birthdate', SYSDATETIME(), SYSDATETIME(),'1'),
('00000000000000000000000000000000','latest_login_datetime', SYSDATETIME(), SYSDATETIME(),'1'),
('00000000000000000000000000000000','email_verified', SYSDATETIME(), SYSDATETIME(),'1');

INSERT INTO [auth].[scope_master]([scope],[description],[confidential_only],[create_datetime],[update_datetime],[status])
VALUES
('openid', N'OpenID Connect authentication', 0, SYSDATETIME(), SYSDATETIME(), 1),
('profile', N'Basic profile claims', 0, SYSDATETIME(), SYSDATETIME(), 1),
('email', N'Email claims', 0, SYSDATETIME(), SYSDATETIME(), 1);

INSERT INTO [auth].[scope_data_key]([scope],[data_key],[create_datetime],[update_datetime],[status])
VALUES
('openid', 'sub', SYSDATETIME(), SYSDATETIME(), 1),
('profile', 'name', SYSDATETIME(), SYSDATETIME(), 1),
('profile', 'preferred_username', SYSDATETIME(), SYSDATETIME(), 1),
('profile', 'birthdate', SYSDATETIME(), SYSDATETIME(), 1),
('email', 'email', SYSDATETIME(), SYSDATETIME(), 1),
('email', 'email_verified', SYSDATETIME(), SYSDATETIME(), 1);

COMMIT TRAN;
