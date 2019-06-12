package com.callsign.saml.config.filters;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlMessageStore;
import org.springframework.security.saml.SamlRequestMatcher;
import org.springframework.security.saml.provider.SamlFilter;
import org.springframework.security.saml.provider.identity.IdentityProviderService;
import org.springframework.security.saml.provider.identity.IdpInitiatedLoginFilter;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class IdpInitatedLoginFilterCustom extends SamlFilter<IdentityProviderService> {
    private static Log logger = LogFactory.getLog(IdpInitiatedLoginFilter.class);
    private final SamlRequestMatcher requestMatcher;
    private final SamlMessageStore<Assertion, HttpServletRequest> assertionStore;
    private String postBindingTemplate;

    public IdpInitatedLoginFilterCustom(SamlProviderProvisioning<IdentityProviderService> provisioning, SamlMessageStore<Assertion, HttpServletRequest> assertionStore) {
        this(provisioning, assertionStore, new SamlRequestMatcher(provisioning, "init"));
    }

    public IdpInitatedLoginFilterCustom(SamlProviderProvisioning<IdentityProviderService> provisioning, SamlMessageStore<Assertion, HttpServletRequest> assertionStore, SamlRequestMatcher requestMatcher) {
        super(provisioning);
        this.postBindingTemplate = "/templates/saml2-post-binding.vm";
        this.requestMatcher = requestMatcher;
        this.assertionStore = assertionStore;
    }

    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (this.requestMatcher.matches(request) && authentication != null && authentication.isAuthenticated()) {
            IdentityProviderService provider = (IdentityProviderService) this.getProvisioning().getHostedProvider();
            ServiceProviderMetadata recipient = this.getTargetProvider(request);
            AuthenticationRequest authenticationRequest = this.getAuthenticationRequest(request);
            Assertion assertion = this.getAssertion(authentication, provider, recipient);
            this.assertionStore.addMessage(request, assertion.getId(), assertion);
            Response r = provider.response(authenticationRequest, assertion, recipient);
            Endpoint acsUrl = provider.getPreferredEndpoint(recipient.getServiceProvider().getAssertionConsumerService(), Binding.POST, -1);
            logger.debug(String.format("Sending assertion for SP:%s to URL:%s using Binding:%s", recipient.getEntityId(), acsUrl.getLocation(), acsUrl.getBinding()));
            String relayState = request.getParameter("RelayState");
            String encoded;
            if (acsUrl.getBinding() == Binding.REDIRECT) {
                encoded = provider.toEncodedXml(r, true);
                UriComponentsBuilder url = UriComponentsBuilder.fromUriString(acsUrl.getLocation());
                url.queryParam("SAMLRequest", new Object[]{UriUtils.encode(encoded, StandardCharsets.UTF_8.name())});
                if (StringUtils.hasText(relayState)) {
                    url.queryParam("RelayState", new Object[]{UriUtils.encode(relayState, StandardCharsets.UTF_8.name())});
                }

                String redirect = url.build(true).toUriString();
                response.sendRedirect(redirect);
            } else {
                if (acsUrl.getBinding() != Binding.POST) {
                    throw new SamlException("Unsupported binding:" + acsUrl.getBinding());
                }

                encoded = provider.toEncodedXml(r, false);
                Map<String, Object> model = new HashMap();
                model.put("action", acsUrl.getLocation());
                model.put("SAMLResponse", encoded);
                if (StringUtils.hasText(relayState)) {
                    model.put("RelayState", relayState);
                }

                this.processHtml(request, response, this.getPostBindingTemplate(), model);
            }
        } else {
            filterChain.doFilter(request, response);
        }

    }

    protected ServiceProviderMetadata getTargetProvider(HttpServletRequest request) {
        String entityId = request.getParameter("sp");
        return (ServiceProviderMetadata) ((IdentityProviderService) this.getProvisioning().getHostedProvider()).getRemoteProvider(entityId);
    }

    protected AuthenticationRequest getAuthenticationRequest(HttpServletRequest request) {
        return null;
    }

    protected Assertion getAssertion(Authentication authentication, IdentityProviderService provider, ServiceProviderMetadata recipient) {
        return provider.assertion(recipient, authentication.getName() + ".antonijevic@gmail.com", NameId.PERSISTENT);
    }

    public String getPostBindingTemplate() {
        return this.postBindingTemplate;
    }

    public IdpInitatedLoginFilterCustom setPostBindingTemplate(String postBindingTemplate) {
        this.postBindingTemplate = postBindingTemplate;
        return this;
    }
}
