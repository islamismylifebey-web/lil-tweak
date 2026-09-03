\set ON_ERROR_STOP on

REVOKE CREATE ON SCHEMA public FROM PUBLIC;

SELECT format('CREATE ROLE %I LOGIN', :'migrator_role')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'migrator_role')
\gexec

SELECT format('CREATE ROLE %I LOGIN', :'app_role')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_role')
\gexec

SELECT format('ALTER ROLE %I PASSWORD %L', :'migrator_role', :'migrator_password')
\gexec

SELECT format('ALTER ROLE %I PASSWORD %L', :'app_role', :'app_password')
\gexec

GRANT CONNECT ON DATABASE lil_tweak TO :"migrator_role", :"app_role";
GRANT USAGE, CREATE ON SCHEMA public TO :"migrator_role";
GRANT USAGE ON SCHEMA public TO :"app_role";
