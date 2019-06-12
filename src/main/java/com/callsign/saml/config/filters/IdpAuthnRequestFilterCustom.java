package com.callsign.saml.config.filters;

import org.springframework.http.HttpMethod;
import org.springframework.security.saml.SamlMessageStore;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;

import javax.servlet.http.HttpServletRequest;

public class IdpAuthnRequestFilterCustom extends IdpInitatedLoginFilterCustom {
    public IdpAuthnRequestFilterCustom(SamlProviderProvisioning<IdentityProviderService> provisioning, SamlMessageStore<Assertion, HttpServletRequest> assertionStore) {
        this(provisioning, assertionStore, new SamlRequestMatcher(provisioning, "SSO"));
    }

    public IdpAuthnRequestFilterCustom(SamlProviderProvisioning<IdentityProviderService> provisioning, SamlMessageStore<Assertion, HttpServletRequest> assertionStore, SamlRequestMatcher requestMatcher) {
        super(provisioning, assertionStore, requestMatcher);
    }

    protected ServiceProviderMetadata getTargetProvider(HttpServletRequest request) {
        IdentityProviderService provider = (IdentityProviderService) this.getProvisioning().getHostedProvider();
        AuthenticationRequest authn = this.getAuthenticationRequest(request);
        provider.validate(authn);
        return (ServiceProviderMetadata) provider.getRemoteProvider(authn);
    }

    protected AuthenticationRequest getAuthenticationRequest(HttpServletRequest request) {
        IdentityProviderService provider = (IdentityProviderService) this.getProvisioning().getHostedProvider();
        String param = request.getParameter("SAMLRequest");
        return (AuthenticationRequest) provider.fromXml(param, true, HttpMethod.GET.name().equalsIgnoreCase(request.getMethod()), AuthenticationRequest.class);
    }
}
