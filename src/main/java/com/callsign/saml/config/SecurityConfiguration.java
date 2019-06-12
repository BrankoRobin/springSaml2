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

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.config.RotatingKeys;
import org.springframework.security.saml.provider.identity.config.SamlIdentityProviderSecurityConfiguration;
import org.springframework.security.saml.provider.identity.config.SamlIdentityProviderSecurityDsl;
import org.springframework.security.saml.saml2.metadata.NameId;

import static java.util.Arrays.asList;
import static org.springframework.security.saml.saml2.encrypt.DataEncryptionMethod.AES128_CBC;
import static org.springframework.security.saml.saml2.encrypt.KeyEncryptionMethod.RSA_1_5;
import static org.springframework.security.saml.saml2.signature.AlgorithmMethod.RSA_SHA512;
import static org.springframework.security.saml.saml2.signature.DigestMethod.SHA512;

@EnableWebSecurity
public class SecurityConfiguration {

    @Configuration
    @Order(1)
    public static class SamlSecurity extends SamlIdentityProviderSecurityConfiguration {

        private final AppConfig appConfig;
        private final BeanConfig beanConfig;
        private final SamlIdentityProviderSecurityDsl identityProvider;

        private final CustomAuthenticationProvider customAuthenticationProvider;

        public SamlSecurity(BeanConfig beanConfig, @Qualifier("appConfig") AppConfig appConfig,
                            SamlIdentityProviderSecurityDsl identityProvider,
                            CustomAuthenticationProvider customAuthenticationProvider) {
            super("/saml/idp/", beanConfig);
            this.appConfig = appConfig;
            this.beanConfig = beanConfig;
            this.identityProvider = identityProvider;
            this.customAuthenticationProvider = customAuthenticationProvider;

        }

        @Override
        public void configure(WebSecurity web) throws Exception {
            web.ignoring()
                    .antMatchers("/metadata/**")
                    .antMatchers("/identity")
                    .antMatchers("/configuration/**");
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.authenticationProvider(customAuthenticationProvider);

        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            super.configure(http);
            http.userDetailsService(beanConfig.userDetailsService()).formLogin()
                    .loginPage("/login").loginProcessingUrl("/loginSecure").permitAll();

            http.apply(identityProvider)
                    .prefix(getPrefix())
                    .useStandardFilters()
                    .entityId("https://branko.my.salesforce.com")
                    .alias("boot-sample-idp")
                    .signMetadata(true)
                    .encryptAssertions(true, RSA_1_5, AES128_CBC)
                    .signatureAlgorithms(RSA_SHA512, SHA512)
                    .wantRequestsSigned(true)
                    .singleLogout(true)
                    .nameIds(asList(NameId.EMAIL))
                    .rotatingKeys(getKeys());

        }

        private RotatingKeys getKeys() {
            return new RotatingKeys()
                    .setActive(
                            new SimpleKey()
                                    .setName("active-idp-key")
                                    .setPrivateKey("-----BEGIN RSA PRIVATE KEY-----\n" +
                                            "Proc-Type: 4,ENCRYPTED\n" +
                                            "DEK-Info: DES-EDE3-CBC,DD358F733FD89EA1\n" +
                                            "\n" +
                                            "e/vEctkYs/saPsrQ57djWbW9YZRQFVVAYH9i9yX9DjxmDuAZGjGVxwS4GkdYqiUs\n" +
                                            "f3jdeT96HJPKBVwj88dYaFFO8g4L6CP+ZRN3uiKXGvb606ONp1BtJBvN0b94xGaQ\n" +
                                            "K9q2MlqZgCLAXJZJ7Z5k7aQ2NWE7u+1GZchQSVo308ynsIptxpgqlpMZsh9oS21m\n" +
                                            "V5SKs03mNyk2h+VdJtch8nWwfIHYcHn9c0pDphbaN3eosnvtWxPfSLjo274R+zhw\n" +
                                            "RA3KNp2bdyfidluTXj40GOYObjfcm1g3sSMgZZqpY3EQUc8DEokfXQZghfBvoEe/\n" +
                                            "GB0k/+StrFNl0qAdOrA6PBndlySp6STwQVAsKsKlJneRO3nAHMlZ7kenHgPunACI\n" +
                                            "IYKIPqPKGVTm1k2FuEPDuwsneEStiThtlvQ4Nu+k6hbuplaKlZ8C2xsubzVQ3rFU\n" +
                                            "KNEhU65DagDH9wR9FzEXpTYUgwrr2vNRyd0TqcSxUpUx4Ra0f3gp5/kojufD8i1y\n" +
                                            "Fs88e8L3g1to1hCsz8yIYIiFjYNf8CuH8myDd2KjqJlyL8svKi+M2pPYl9vY1m8L\n" +
                                            "u4/3ZPMrGUvtAKixBZNzj95HPX0UtmC2kPMAvdvgzaPlDeH5Ee0rzPxnHI21lmyd\n" +
                                            "O6Sb3tc/DM9xbCCQVN8OKy/pgv1PpHMKwEE7ELpDRoVWS8DzZ43Xfy1Rm8afADAv\n" +
                                            "39oj4Gs08FblaHnOSP8WOr4r9SZbF1qmlMw7QkHeaF+MJzmG3d0t2XsDzKfc510m\n" +
                                            "gEbiD/L3Z8czwXM5g2HciAMOEVhZQJvK62KwMyOmNqBnEThBN+apsQ==\n" +
                                            "-----END RSA PRIVATE KEY-----")
                                    .setPassphrase("idppassword")
                                    .setCertificate(" -----BEGIN CERTIFICATE-----\n" +
                                            "MIIChTCCAe4CCQDo0wjPUK8sMDANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UEBhMC\n" +
                                            "VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
                                            "A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxDDAKBgNVBAsMA2lkcDEhMB8GA1UE\n" +
                                            "AwwYaWRwLnNwcmluZy5zZWN1cml0eS5zYW1sMB4XDTE4MDUxNDE0NTUyMVoXDTI4\n" +
                                            "MDUxMTE0NTUyMVowgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9u\n" +
                                            "MRIwEAYDVQQHDAlWYW5jb3V2ZXIxHTAbBgNVBAoMFFNwcmluZyBTZWN1cml0eSBT\n" +
                                            "QU1MMQwwCgYDVQQLDANpZHAxITAfBgNVBAMMGGlkcC5zcHJpbmcuc2VjdXJpdHku\n" +
                                            "c2FtbDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2EuygAucRBWtYifgEH/E\n" +
                                            "rVUive4dZdqo72Bze4MbkPuTKLrMCLB6IXxt1p5lu+tr0JxOiRO3KFVOO3D0l+j9\n" +
                                            "zOow4g+JdoMQsjSzA6HtL/D9ZjXP6iUxFCYx+qmnVl3X9ipBD/HVKOBlzIqeXTSa\n" +
                                            "5D17uxPQVxK64UDOI3CyY4cCAwEAATANBgkqhkiG9w0BAQsFAAOBgQAj+6b6dlA6\n" +
                                            "SitTfz44LdnFSW9mYaeimwPP8ZtU7/3EJCzLd5eq7N/0kYPNVclZvB45I0UMT77A\n" +
                                            "HWrNyScm56MTcEpSuHhJHAqRAgJKbciCTNsFI928EqiWSmu//w0ASBN3bVa8nv8/\n" +
                                            "rafuutCq3RskTkHVZnbT5Xa6ITEZxSncow==\n" +
                                            "----END CERTIFICATE-----")
                    );
        }
    }

    @Configuration
    public static class AppSecurity extends WebSecurityConfigurerAdapter {
        private final BeanConfig beanConfig;
        private final CustomAuthenticationProvider customAuthenticationProvider;

        public AppSecurity(BeanConfig beanConfig, CustomAuthenticationProvider customAuthenticationProvider) {
            this.beanConfig = beanConfig;
            this.customAuthenticationProvider = customAuthenticationProvider;
        }

        @Override
        public void configure(WebSecurity web) throws Exception {
            web.ignoring()
                    .antMatchers("/metadata/**")
                    .antMatchers("/identity")
                    .antMatchers("/configuration/**");
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.authenticationProvider(customAuthenticationProvider);

        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .csrf().disable()
                    .antMatcher("/**")
                    .authorizeRequests()
                    .antMatchers("/**").authenticated()
                    .antMatchers("/resources/**").permitAll()
                    .antMatchers("/loginSecure").permitAll()
                    .and()
                    .userDetailsService(beanConfig.userDetailsService())
                    .formLogin()
                    .loginPage("/login").loginProcessingUrl("/loginSecure").permitAll();
        }
    }
}
