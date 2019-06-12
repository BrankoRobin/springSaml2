/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package com.callsign.saml.config;

import com.callsign.saml.config.filters.IdpAuthnRequestFilterCustom;
import com.callsign.saml.config.filters.IdpInitatedLoginFilterCustom;
import com.callsign.saml.config.filters.ThreadLocalSamlConfigurationFilterCustom;
import com.callsign.saml.config.filters.ThreadLocalSamlConfigurationRepositoryCustom;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.saml.provider.SamlServerConfiguration;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.config.StaticSamlConfigurationRepository;
import org.springframework.security.saml.provider.config.ThreadLocalSamlConfigurationFilter;
import org.springframework.security.saml.provider.config.ThreadLocalSamlConfigurationRepository;
import org.springframework.security.saml.provider.identity.config.SamlIdentityProviderSecurityDsl;
import org.springframework.security.saml.provider.identity.config.SamlIdentityProviderServerBeanConfiguration;

import javax.servlet.Filter;

@Configuration
public class BeanConfig extends SamlIdentityProviderServerBeanConfiguration {
    private final AppConfig config;

    public BeanConfig(AppConfig config) {
        this.config = config;
    }

    @Override
    protected SamlServerConfiguration getDefaultHostSamlServerConfiguration() {
        return config;
    }

    @Override
    public Filter idpInitatedLoginFilter() {
        return new IdpInitatedLoginFilterCustom(this.getSamlProvisioning(), this.samlAssertionStore());
    }

    @Override
    public Filter idpAuthnRequestFilter() {
        return new IdpAuthnRequestFilterCustom(this.getSamlProvisioning(), this.samlAssertionStore());
    }

    @Bean
    public static SamlIdentityProviderSecurityDsl identityProvider() {
        return new SamlIdentityProviderSecurityDsl();
    }

    @Override
    public ThreadLocalSamlConfigurationRepositoryCustom samlConfigurationRepository() {
        return new ThreadLocalSamlConfigurationRepositoryCustom(new StaticSamlConfigurationRepository(this.getDefaultHostSamlServerConfiguration()));
    }

    @Override
    public Filter samlConfigurationFilter() {
        return new ThreadLocalSamlConfigurationFilterCustom((ThreadLocalSamlConfigurationRepositoryCustom) this.samlConfigurationRepository());
    }


    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("branko")
                .password("branko")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(userDetails);
    }
}
