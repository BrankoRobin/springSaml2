# Spring Saml2 identity provider

**p2-saml-api** is Spring boot application that acts as identity provider.
For POC purpose service provider definitions are defined in sp1- and sp2- metadata files (resource folder).
Identity provider instance is fixed and defined in **SecurityConfiguration** class (most important entity-id and keys for identity provider)
Project is using **Spring Security SAML v2** library where is entire Spring OpenSaml implementation.

###   Configuration for integration with service providers
Before running Spring boot app locally there is a few things to adjust.
 1. SecurityConfiguration  .entityId("...") - set etity-id for idp (for salesforce domain link).
 2. From src/main/resource folder edit **saml-idp-metadata.xml** file edit the entityID element.
 3. For *salesforce.com* integration login in sales force and in SSO integration create new Single-Sign-On configuration from **saml-idp-metadata.xml**, and download the metadata xml file and put the content in **sp1-metadata.xml** file in resource folder.
 4. For *sptest.iamshowcase.com*  go to Instructions/IDP initiated SSO and load the **saml-idp-metadata.xml** then download the sp metadata xml content to **sp2-metadata.xml** file form resource folder. Login url will be generated e.g *https://sptest.iamshowcase.com/ixs?idp=a058f305cb1126eaa86fd2dc97ac75bdea56b137*
 5. In **CustomAuthenticationProvider** where the simple custom security logic is to check input word from login page (in real implementation probably etg will be called)
 6. In **IdpInitatedLoginFilterCustom** class there is getAssertion method where user name is modified to be a email (email should be a username on salesforce), line to modified:
  **return provider.assertion(recipient, authentication.getName() + {the rest of salesforce username}, NameId.PERSISTENT);**

###   Running the spring boot idp application
1. Before running spring boot application run the **mvn clean install**
2. Run the spring boot app port 8081 and root-path /sample-idp, on startup identity provider instance will be defined, service providers can be defined in runtime
3. *http://localhost:8081/sample-idp/configuration/sp1* for salesforce sp definition and *http://localhost:8081/sample-idp/configuration/sp1*2 for sptest sp definition
4. now you can login with salesforce or sptest, on custom login page callsign id is "branko", that can be changed locally in **CustomAuthenticationProvider** where the simple custom security logic is to check this word (in real implementation probably etg will be called)

 ###   Further Notice
 1. Saml Keys are hardcoded, should be fetched from some url
 2. Also keys should be different for each service provider
 3. Sp definitions should be stored in db
 4. Custom authentication logic should be replaced with P2 call to etg or other authentication component
 5. Custom login page should be replaces with one from web sdk

 ###   Spring Saml reference
 1. *https://github.com/spring-projects/spring-security-saml* - the main directions for this POC project is from this project
 (there is core source code fo spring saml2 livrary and samples for idp and sp), also documentation links is present od document page.
