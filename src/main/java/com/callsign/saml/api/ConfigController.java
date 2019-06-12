package com.callsign.saml.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.config.RotatingKeys;
import org.springframework.security.saml.provider.identity.config.ExternalServiceProviderConfiguration;
import org.springframework.security.saml.provider.identity.config.SamlIdentityProviderSecurityConfiguration;
import org.springframework.security.saml.provider.identity.config.SamlIdentityProviderSecurityDsl;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static java.util.Arrays.asList;
import static org.springframework.security.saml.saml2.encrypt.DataEncryptionMethod.AES128_CBC;
import static org.springframework.security.saml.saml2.encrypt.KeyEncryptionMethod.RSA_1_5;
import static org.springframework.security.saml.saml2.signature.AlgorithmMethod.RSA_SHA512;
import static org.springframework.security.saml.saml2.signature.DigestMethod.SHA512;

@RestController
@RequestMapping()
public class ConfigController {

    private Boolean check = false;

    @Autowired
    SamlIdentityProviderSecurityDsl identityProvider;

    @Autowired
    SamlIdentityProviderSecurityConfiguration samlConfig;

    @GetMapping(value = "/configuration/{serviceProvider}")
    public String setNewProvider(@PathVariable String serviceProvider) {
        ExternalServiceProviderConfiguration sp = new ExternalServiceProviderConfiguration()
                .setAlias("new-example-" + serviceProvider)
                .setLinktext("new service provider - " + serviceProvider)
                .setMetadata("http://localhost:8081/sample-idp/metadata/" + serviceProvider)
                .setSkipSslValidation(true);
        identityProvider.serviceProvider(sp);

        return "created - " + serviceProvider;
    }


    @GetMapping(value = "/metadata/{serviceProvider}", produces = "application/xml")
    public ResponseEntity<byte[]> downloadFile(@PathVariable String serviceProvider) throws IOException {

        byte[] content = null;
        try {
            Path path = Paths.get(getClass().getClassLoader()
                    .getResource(serviceProvider + "-metadata.xml").toURI());
            content = Files.readAllBytes(path);

        } catch (URISyntaxException e) {
            e.printStackTrace();
        }

        return ResponseEntity.ok()
                .contentLength(content.length)
                .header(HttpHeaders.CONTENT_TYPE, "application/xml")
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + "sp1-metadata.xml")
                .body(content);
    }

}
