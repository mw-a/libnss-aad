# libnss-aad

## Compiling

1) Fetch source code:

```terminal
git clone https://github.com/aad-for-linux/libnss-aad

cd libnss_aad
```

2) Compile:

```terminal
make
```

4) Install:

```terminal
sudo make install
```

## Configuration

1) Azure:

- Login to the [Microsoft Azure Portal](portal.azure.com).

- In the sidebar on the left, navigate to "Azure Active Directory", then choose "App registrations (Preview)", then select "New registration".

  - Choose a Name e.g. `Name Service Switch for Azure Active Directory`.

  - For Supported account types select `Accounts in this organizational directory only (Organization Name)`.

- Next click "Register", down at the bottom.

- From the "Overview" page, under "Manage", select "API permissions".

  - Delete any existing permissions (The delegated permission, `Microsoft Graph (1)`, `User.Read` seems to be added by default).

  - Select "Add a permission", then under "Select an API", "Microsoft APIs", "Commonly used Microsoft APIs", choose `Microsoft Graph`.

    - Choose "Application permissions".

    - Under "Select permissions", choose `Application.Read.All` and `User.Read.All`.

    - This allows the module to determine the AppId of the `Tenant Schema
      Extension App` for use in extension attribute names as well as the values
      of these attributes of all users using its own credentials acquired using the
      Client Credential Flow.


2) NSS:

*These instructions assume that the host system is either Debian or one of its derivatives.*

`/etc/libnss-aad.conf`

```mustache
{
  "client": {
    "id": "{{client_id}}",
    "secret": "{{client_secret}}"
  },
  "tenant": "{{tenant}}",
  "domain": "{{domain}}",
  "user": {
    "group": "users",
    "shell": "/bin/bash"
  },
  "debug": true # to optionally enable debugging mode
}
```

**NOTE: For now, `client.secret` must be URL-encoded.**

`/etc/nsswitch.conf`

```
passwd:         compat aad
group:          compat
shadow:         compat aad
```

## Tools

**Syntax Checking and Code Formatting**

```terminal
cp .githooks/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### getent

    gentent passwd $(whoami)

- [getent](https://en.wikipedia.org/wiki/Getent)

### id

    id $(whoami)

- [id: Print user identity](https://www.gnu.org/software/coreutils/manual/coreutils.html#id-invocation)

## Resources

- [Azure Active Directory Documentation](https://docs.microsoft.com/en-us/azure/active-directory)

- [Service to service calls using client credentials (shared secret or certificate)](https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-oauth2-client-creds-grant-flow)

- [Azure AD v2.0 Protocols (Postman Collection)](https://app.getpostman.com/view-collection/8f5715ec514865a07e6a?referrer=https%3A%2F%2Fapp.getpostman.com%2Frun-collection%2F8f5715ec514865a07e6a)

- [System Databases and Name Service Switch](https://www.gnu.org/software/libc/manual/html_node/Name-Service-Switch.html)

## See also

- [puppet-aad](https://github.com/Jnchi/puppet-aad)
