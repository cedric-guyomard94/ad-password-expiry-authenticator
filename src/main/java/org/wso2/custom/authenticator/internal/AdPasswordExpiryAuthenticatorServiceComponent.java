package org.wso2.custom.authenticator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.custom.authenticator.AdPasswordExpiryAuthenticator;

public class AdPasswordExpiryAuthenticatorServiceComponent implements BundleActivator {

    private static final Log log = LogFactory.getLog(AdPasswordExpiryAuthenticatorServiceComponent.class);
    private ServiceRegistration<?> serviceRegistration;
    private static RealmService realmService;

    @Override
    public void start(BundleContext context) {
        ServiceReference<RealmService> realmRef = context.getServiceReference(RealmService.class);
        if (realmRef != null) {
            realmService = context.getService(realmRef);
        }

        AdPasswordExpiryAuthenticator authenticator = new AdPasswordExpiryAuthenticator();
        serviceRegistration = context.registerService(
                ApplicationAuthenticator.class.getName(), authenticator, null);
        log.info("AdPasswordExpiryAuthenticator registered successfully.");
    }

    @Override
    public void stop(BundleContext context) {
        if (serviceRegistration != null) {
            serviceRegistration.unregister();
        }
        log.info("AdPasswordExpiryAuthenticator unregistered.");
    }

    public static RealmService getRealmService() {
        return realmService;
    }
}
