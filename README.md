# <img src="https://github.com/sudesh1611/SwayamVaha/assets/10352292/1a0b31f3-79c9-4dc3-a6f9-869123096b8e" width="30" height="30"> SwayamVaha


A Django based dashboard to manage vulnerablities reported by Twistlock and Blackduck. SwayamVaha provides functionality to mark vulnerabilities false positives so that in future scans, they can be automatically ignored. SwayamVaha with the help of [JiraAuto](https://github.com/sudesh1611/JiraAuto) manages a database of mapping of Jira Issues raised for vulnerabilities. SwayamVaha exposes REST APIs that are used by other projects to fetch/populate data.

## Requirements

SwayamVaha requires Python 3.6 or greater. Additional dependencies can be resolved by executing following two commands:

>`pip3 install -r dashboard/core/requirements.txt`
>
>`pip3 install -r requirements.txt`

SwayamVaha uses PostgreSQL as backend database. There is plenty of documentation available online for installing and configuring PostgreSQL. One can follow this popular reference from [DigitalOcean](https://www.digitalocean.com/community/tutorials/how-to-use-postgresql-with-your-django-application-on-ubuntu-22-04)


## Configuration

Following section describes how to configure WebApp.

### One/First Time Setup

#### Database Setup

1. On the system having PostgreSQL, use following command to switch to postgres user:

    >`sudo -i -u postgres`

1. Create Database in Postgres for WebApp with name **dashboard**:

    >`CREATE DATABASE dashboard;`

1. Create a user:

    >`CREATE USER admin WITH PASSWORD 'Password123!';`

1. Configure Database and grant new user access to Database:

    >`ALTER ROLE admin SET client_encoding TO 'utf8';`
    >
    >`ALTER ROLE admin SET default_transaction_isolation TO 'read committed';`
    >
    >`ALTER ROLE admin SET timezone TO 'UTC';`
    >
    >`GRANT ALL PRIVILEGES ON DATABASE dashboard TO admin;`

#### Environment Variable Setup

On the system where this WebApp needs to run, export following variables:

1. PostgreSql Username and password:

    >`export PSQL_USERNAME='admin'`
    >
    >`export PSQL_PASSWORD='Password123!'`

1. Jira Personal Access Token Value:

    Link describing how to generate Jira Personal Access Tokens: [Using Personal Access Tokens](https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html)

    >`export JIRA_PAT_VALUE=APojWtGZUyNDUyMzAzaert4ahSdeTIBxl68yHchnVbiuN7rR`

1. WebApp's Username and Password:

    After generating username and password for the WebApp using the steps given in [next section](#create-webapp-user-and-migrations-for-the-first-time), export them

    >`export UI_USERNAME=admin`
    >
    >`export UI_PASSWORD=ChangeMe`


### Configuration Files

The `dashboard/core/configs` folder contains some of the files that are required to be modified according to the environment and requirements. Following are the files that are used by WebApp and must me modified (other config files can be ignored):

- `blackduckproject.py` (Optional): Add the Name and Corresponding ID of the BlackDuck Projects. See example for details.

- `blackduckreport.py`: Update the absolute path to the directory where BlackDuck Reports are stored. See [BlackDuckAuto](https://github.com/sudesh1611/BlackDuckAuto) for more info about this path.

- `pdfreport.py`: Update the path to the Firefox Webdriver Binary which is used for generating Pdf Report.

- `twistlockreport.py`: Update the absolute path to the directory where Twistlock Reports are stored. See [TwistlockAuto](https://github.com/sudesh1611/TwistlockAuto) for more info about this path.

- `webapp.py`:
    - Update the LOG_FILE_PATH to store the logs of the WebApp.
    - Change the SECRET_KEY to something else.
    - Update the value of POSTGRESQL_DOMAIN_IP i.e. domain/IP address of system hosting PostgreSQL.
    - Update the value of POSTGRESQL_PORT i.e. port on which PostgreSQL is exposed on system hosting PostgreSQL.
    - Update POSTGRESQL_DB_NAME to the name of Database created in above steps.
    - Update IP/domain in HOSTNAME to the IP/domain of the system on which this WebApp is hosted. Update port if using other than 80 to host this WebApp.


### Create WebApp user and Migrations for the First Time

From root directory of this WebApp, execute following:

1. Make Migrations:

    >`python3 manage.py makemigrations`

1. Apply Migrations:

    >`python3 manage.py migrate`

1. Create User:

    >`python3 manage.py createsuperuser`

    Make sure you export the WebApp Username and Password as environment variables as mentioned above in [WebApp's Username and Password](#environment-variable-setup)

## Execution

Use the following command to start the WebApp from the root of this WebApp:

>`python3 manage.py runserver 0.0.0.0:80`
