/*
 * Custom authenticator for IS 7.1.0 that detects AD "must change password" (error 773)
 * and surfaces a structured error message in the app-native auth response.
 *
 * Root cause context: ReadOnlyLDAPUserStoreManager.bindAsUser() swallows the NamingException
 * and returns false, losing the AD sub-error code. This authenticator performs a secondary
 * direct LDAP bind when the normal auth fails, to recover the AD-specific error code.
 */
package org.wso2.custom.authenticator;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AdPasswordExpiryAuthenticator extends BasicAuthenticator {

    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(AdPasswordExpiryAuthenticator.class);

    static final String AUTHENTICATOR_NAME = "AdPasswordExpiryAuthenticator";
    static final String AUTHENTICATOR_FRIENDLY_NAME = "AD Password Expiry Authenticator";

    // AD sub-error codes embedded in the NamingException message
    private static final String AD_ERROR_MUST_CHANGE_PASSWORD = "data 773";
    private static final String AD_ERROR_PASSWORD_EXPIRED     = "data 532";

    // Message ID surfaced to the client app in the app-native auth response
    static final String MSG_ID_MUST_CHANGE_PASSWORD = "AD-60001";
    static final String MSG_ID_PASSWORD_EXPIRED     = "ABA-60003"; // reuse IS standard code

    // LDAP user store property keys (consistent with AbstractLDAPUserStoreManager)
    private static final String PROP_CONNECTION_URL     = "ConnectionURL";
    private static final String PROP_CONNECTION_TIMEOUT = "LDAPConnectionTimeout";
    private static final String PROP_USER_DN_PATTERN    = "UserDNPattern";
    private static final String PROP_USER_NAME_ATTRIBUTE = "UserNameAttribute";
    private static final String PROP_USER_SEARCH_BASE   = "UserSearchBase";

    private static final String AUTHENTICATOR_MESSAGE_KEY = "authenticatorMessage";

    @Override
    public String getName() {
        return AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {
        return AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
            HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            super.processAuthenticationResponse(request, response, context);
        } catch (AuthenticationFailedException e) {
            // Normal auth failed — probe AD for a specific sub-error code
            log.info("[AdPasswordExpiryAuthenticator] Basic auth failed, probing for AD-specific error");
            String username = request.getParameter("username");
            String password  = request.getParameter("password");

            if (StringUtils.isNotBlank(username) && StringUtils.isNotBlank(password)) {
                String tenantDomain       = MultitenantUtils.getTenantDomain(username);
                String tenantAwareUser    = MultitenantUtils.getTenantAwareUsername(username);
                String userStoreDomain    = UserCoreUtil.extractDomainFromName(tenantAwareUser);
                String usernameOnly       = UserCoreUtil.removeDomainFromName(tenantAwareUser);
                log.info("[AdPasswordExpiryAuthenticator] Probing AD: username=" + usernameOnly + ", domain=" + userStoreDomain + ", tenant=" + tenantDomain);

                String adCode = probeAdError(usernameOnly, password, userStoreDomain, tenantDomain, context);
                log.info("[AdPasswordExpiryAuthenticator] Probe result: " + adCode);

                if (AD_ERROR_MUST_CHANGE_PASSWORD.equals(adCode)) {
                    log.info("AD error 773 (must change password) detected for user in store: " + userStoreDomain);
                    setAuthenticatorMessage(context, MSG_ID_MUST_CHANGE_PASSWORD,
                            "Your AD password must be changed before you can log in. " +
                            "Please contact your administrator or change your password in Active Directory.");
                } else if (AD_ERROR_PASSWORD_EXPIRED.equals(adCode)) {
                    log.info("AD error 532 (password expired) detected for user in store: " + userStoreDomain);
                    setAuthenticatorMessage(context, MSG_ID_PASSWORD_EXPIRED,
                            "Your AD password has expired. Please change it before logging in.");
                }
            }

            // Always rethrow — the IS framework handles the failed status
            throw e;
        }
    }

    /**
     * Performs a direct LDAP bind using the user's credentials and inspects the
     * NamingException message for AD-specific sub-error codes.
     *
     * @return the AD error tag ("data 773", "data 532") or null if not AD / not detectable
     */
    private String probeAdError(String username, String password,
            String userStoreDomain, String tenantDomain, AuthenticationContext context) {

        try {
            AbstractUserStoreManager rootManager = resolveRootStoreManager(tenantDomain, context);
            if (rootManager == null) {
                log.warn("[AdPasswordExpiryAuthenticator] rootManager is null for tenant: " + tenantDomain);
                return null;
            }
            log.debug("[AdPasswordExpiryAuthenticator] rootManager resolved for tenant: " + tenantDomain);

            AbstractUserStoreManager targetManager = resolveTargetStoreManager(rootManager, userStoreDomain);
            if (targetManager == null) {
                log.warn("[AdPasswordExpiryAuthenticator] targetManager is null for domain: " + userStoreDomain);
                return null;
            }
            log.debug("[AdPasswordExpiryAuthenticator] targetManager resolved for domain: " + userStoreDomain);

            RealmConfiguration cfg = targetManager.getRealmConfiguration();
            String connectionUrl = cfg.getUserStoreProperty(PROP_CONNECTION_URL);
            if (StringUtils.isBlank(connectionUrl)) {
                log.warn("[AdPasswordExpiryAuthenticator] ConnectionURL not found in user store config");
                return null;
            }
            log.debug("[AdPasswordExpiryAuthenticator] ConnectionURL: " + connectionUrl);

            String bindDn = buildBindDn(username, cfg);
            if (StringUtils.isBlank(bindDn)) {
                if (log.isDebugEnabled()) {
                    log.debug("Cannot construct bind DN for user — skipping AD probe");
                }
                return null;
            }

            String timeout = StringUtils.defaultIfBlank(
                    cfg.getUserStoreProperty(PROP_CONNECTION_TIMEOUT), "5000");

            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, connectionUrl);
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, bindDn);
            env.put(Context.SECURITY_CREDENTIALS, password);
            env.put("com.sun.jndi.ldap.connect.timeout", timeout);
            env.put("com.sun.jndi.ldap.read.timeout", timeout);

            try {
                log.debug("[AdPasswordExpiryAuthenticator] Attempting LDAP bind with DN: " + bindDn);
                InitialDirContext ctx = new InitialDirContext(env);
                ctx.close();
                log.debug("[AdPasswordExpiryAuthenticator] LDAP bind succeeded — no AD error");
                // Bind succeeded — no AD error to report
                return null;
            } catch (NamingException ne) {
                String errorMsg = ne.getMessage();
                log.info("[AdPasswordExpiryAuthenticator] LDAP NamingException: " + errorMsg);
                String adCode = extractAdErrorCode(errorMsg);
                log.info("[AdPasswordExpiryAuthenticator] Extracted AD code: " + adCode);
                return adCode;
            }

        } catch (Exception ex) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to probe AD LDAP error for user [" + username + "]: " + ex.getMessage());
            }
            return null;
        }
    }

    /**
     * Extracts an AD sub-error tag from a JNDI NamingException message.
     * AD embeds the sub-error in the message as: "... data XXXX, ..."
     */
    private String extractAdErrorCode(String message) {
        if (StringUtils.isBlank(message)) return null;
        if (message.contains(AD_ERROR_MUST_CHANGE_PASSWORD)) return AD_ERROR_MUST_CHANGE_PASSWORD;
        if (message.contains(AD_ERROR_PASSWORD_EXPIRED))     return AD_ERROR_PASSWORD_EXPIRED;
        return null;
    }

    /**
     * Constructs the LDAP bind DN for the user.
     *
     * Prefers UserDNPattern if configured (e.g. "cn={0},ou=Users,dc=example,dc=com").
     * Falls back to UPN format using the domain component of ConnectionURL.
     */
    private String buildBindDn(String username, RealmConfiguration cfg) {
        String dnPattern = cfg.getUserStoreProperty(PROP_USER_DN_PATTERN);
        if (StringUtils.isNotBlank(dnPattern) && dnPattern.contains("{0}")) {
            return dnPattern.replace("{0}", escapeLdapDn(username));
        }

        // UPN fallback: derive domain from DC components of UserSearchBase
        String searchBase = cfg.getUserStoreProperty(PROP_USER_SEARCH_BASE);
        String upnDomain  = dcComponentsToDomain(searchBase);
        if (StringUtils.isNotBlank(upnDomain)) {
            return username + "@" + upnDomain;
        }

        return null;
    }

    /**
     * Converts LDAP DC components to a DNS domain name.
     * "DC=example,DC=com" -> "example.com"
     */
    private String dcComponentsToDomain(String dn) {
        if (StringUtils.isBlank(dn)) return null;
        StringBuilder sb = new StringBuilder();
        for (String part : dn.split(",")) {
            part = part.trim();
            if (part.toLowerCase().startsWith("dc=")) {
                if (sb.length() > 0) sb.append('.');
                sb.append(part.substring(3));
            }
        }
        return sb.length() > 0 ? sb.toString() : null;
    }

    /** Minimal LDAP DN special-character escaping for the CN value. */
    private String escapeLdapDn(String value) {
        return value.replace("\\", "\\\\")
                    .replace(",",  "\\,")
                    .replace("+",  "\\+")
                    .replace("\"", "\\\"")
                    .replace("<",  "\\<")
                    .replace(">",  "\\>")
                    .replace(";",  "\\;");
    }

    private AbstractUserStoreManager resolveRootStoreManager(String tenantDomain,
            AuthenticationContext context) throws UserStoreException {
        try {
            org.wso2.carbon.user.core.service.RealmService realmService =
                    org.wso2.custom.authenticator.internal
                    .AdPasswordExpiryAuthenticatorServiceComponent.getRealmService();
            if (realmService == null) return null;
            org.wso2.carbon.user.api.UserRealm realm =
                    realmService.getTenantUserRealm(
                        realmService.getTenantManager().getTenantId(tenantDomain));
            if (realm == null) return null;
            return (AbstractUserStoreManager) realm.getUserStoreManager();
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Could not obtain UserStoreManager for tenant: " + tenantDomain, e);
            }
            return null;
        }
    }

    private AbstractUserStoreManager resolveTargetStoreManager(AbstractUserStoreManager root,
            String userStoreDomain) {
        if (StringUtils.isBlank(userStoreDomain) ||
                UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equalsIgnoreCase(userStoreDomain)) {
            return root;
        }
        AbstractUserStoreManager secondary =
                (AbstractUserStoreManager) root.getSecondaryUserStoreManager(userStoreDomain);
        if (secondary == null && log.isDebugEnabled()) {
            log.debug("Secondary user store manager not found for domain: " + userStoreDomain);
        }
        return secondary;
    }

    private void setAuthenticatorMessage(AuthenticationContext context,
            String messageId, String message) {
        AuthenticatorMessage msg = new AuthenticatorMessage(
                FrameworkConstants.AuthenticatorMessageType.ERROR,
                messageId,
                message,
                null);
        context.setProperty(AUTHENTICATOR_MESSAGE_KEY, msg);
    }
}
