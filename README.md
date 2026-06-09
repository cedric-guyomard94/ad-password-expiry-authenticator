# AD Password Expiry Authenticator

Custom WSO2 IS 7.1.0 authenticator that detects Active Directory password expiry errors (773, 532) in app-native authentication and surfaces them as structured error messages.

## How it works

Extends `BasicAuthenticator`. On authentication failure, performs a secondary direct LDAP bind to recover the AD sub-error code from the JNDI `NamingException`. Sets an `AuthenticatorMessage` on the context if error 773 (must change password) or 532 (password expired) is detected. User store scoping is automatic — users logging in as `ADSTORE\username` are probed against that store only.

## Build

### Step 1 — Install WSO2 dependencies

These exact patch versions are not published to the public Maven repo. Install them from your IS installation:

```bash
IS_HOME=<IS_HOME>

mvn install:install-file \
  -Dfile=$IS_HOME/repository/components/plugins/org.wso2.carbon.identity.application.authenticator.basicauth_6.8.20.jar \
  -DgroupId=org.wso2.carbon.identity.local.auth.basicauth \
  -DartifactId=org.wso2.carbon.identity.application.authenticator.basicauth \
  -Dversion=6.8.20 -Dpackaging=jar

mvn install:install-file \
  -Dfile=$IS_HOME/repository/components/plugins/org.wso2.carbon.identity.application.authentication.framework_7.8.23.jar \
  -DgroupId=org.wso2.carbon.identity.framework \
  -DartifactId=org.wso2.carbon.identity.application.authentication.framework \
  -Dversion=7.8.23 -Dpackaging=jar

mvn install:install-file \
  -Dfile=$IS_HOME/repository/components/plugins/org.wso2.carbon.user.core_4.10.42.jar \
  -DgroupId=org.wso2.carbon -DartifactId=org.wso2.carbon.user.core \
  -Dversion=4.10.42 -Dpackaging=jar

mvn install:install-file \
  -Dfile=$IS_HOME/repository/components/plugins/org.wso2.carbon.user.api_4.10.42.jar \
  -DgroupId=org.wso2.carbon -DartifactId=org.wso2.carbon.user.api \
  -Dversion=4.10.42 -Dpackaging=jar

# Use the actual Eclipse OSGi JAR filename from your IS plugins folder
mvn install:install-file \
  -Dfile=$IS_HOME/repository/components/plugins/org.eclipse.osgi_<version>.jar \
  -DgroupId=org.osgi -DartifactId=org.osgi.core -Dversion=6.0.0 -Dpackaging=jar
```

### Step 2 — Build

```bash
mvn clean package
```

Output: `target/org.wso2.custom.authenticator.ad.password.expiry-1.0.0.jar`

## Deploy

```bash
cp target/org.wso2.custom.authenticator.ad.password.expiry-1.0.0.jar \
   <IS_HOME>/repository/components/dropins/
```

Restart IS and confirm registration in `<IS_HOME>/repository/logs/wso2carbon.log`:

```
INFO  AdPasswordExpiryAuthenticatorServiceComponent - AdPasswordExpiryAuthenticator registered successfully.
```

## Configure

1. Log in to IS Console (`https://<host>:9443/console`)
2. Go to **Applications** → your application → **Sign-in Method**
3. In Step 1, remove `BasicAuthenticator` and add **AD Password Expiry Authenticator**
4. Click **Update**

## Client application

On `FAIL_INCOMPLETE`, inspect the `messages` array:

```json
{
  "flowStatus": "FAIL_INCOMPLETE",
  "nextStep": {
    "messages": [
      {
        "type": "ERROR",
        "messageId": "AD-60001",
        "message": "Your AD password must be changed before you can log in."
      }
    ]
  }
}
```

| `messageId` | AD error | Suggested action |
|---|---|---|
| `AD-60001` | 773 — must change password at next logon | Redirect to AD password change portal |
| `ABA-60003` | 532 — password expired, or generic failure | Show appropriate message or redirect |

## Notes

- Custom implementation — not a supported WSO2 component. Retest after IS upgrades.
- Performs one additional LDAP bind per failed login. Timeout controlled by `LDAPConnectionTimeout` in the user store config (default 5 seconds).
- Bind DN uses `UserDNPattern` if set, otherwise derives UPN domain from `UserSearchBase` DC components. If neither is available, the probe is skipped and the generic error is returned.
