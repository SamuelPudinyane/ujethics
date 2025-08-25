-- Create the database if it doesn't exist
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = N'ethics')
BEGIN
    CREATE DATABASE ethics;
END
GO
