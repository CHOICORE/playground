package me.choicore.projects.security

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.UUID

@Configuration(proxyBeanMethods = false)
class AuthorizationServerConfiguration {
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Throws(Exception::class)
    fun authorizationServerSecurityFilterChain(httpSecurity: HttpSecurity): SecurityFilterChain {
        val oAuth2AuthorizationServerConfigurer: OAuth2AuthorizationServerConfigurer =
            OAuth2AuthorizationServerConfigurer.authorizationServer()

        httpSecurity
            .securityMatcher(oAuth2AuthorizationServerConfigurer.endpointsMatcher)
            .with(oAuth2AuthorizationServerConfigurer) {
                it.oidc(Customizer.withDefaults())
            }.authorizeHttpRequests { it.anyRequest().authenticated() }
            .exceptionHandling {
                it.defaultAuthenticationEntryPointFor(
                    LoginUrlAuthenticationEntryPoint("/sign-in"),
                    MediaTypeRequestMatcher(MediaType.TEXT_HTML),
                )
            }

        return httpSecurity.build()
    }

    @Bean
    fun registeredClientRepository(jdbcTemplate: JdbcTemplate): RegisteredClientRepository {
        val messagingClient: RegisteredClient =
            RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("messaging-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://127.0.0.1:3000/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://localhost:3000/login/oauth2/code/messaging-client-oidc")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(
                    ClientSettings
                        .builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build(),
                ).build()
        return JdbcRegisteredClientRepository(jdbcTemplate).apply {
            save(messagingClient)
        }
    }

    @Bean
    fun embeddedDatabase(): EmbeddedDatabase =
        EmbeddedDatabaseBuilder()
            .generateUniqueName(true)
            .setType(EmbeddedDatabaseType.H2)
            .setScriptEncoding("UTF-8")
            .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
            .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
            .addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
            .build()

    @Bean
    fun authorizationService(
        jdbcTemplate: JdbcTemplate,
        registeredClientRepository: RegisteredClientRepository,
    ): OAuth2AuthorizationService = JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository)

    @Bean
    fun authorizationConsentService(
        jdbcTemplate: JdbcTemplate,
        registeredClientRepository: RegisteredClientRepository,
    ): OAuth2AuthorizationConsentService = JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository)

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyPairGenerator =
            KeyPairGenerator
                .getInstance("RSA")
                .apply { initialize(2048) }

        val keyPair: KeyPair = keyPairGenerator.generateKeyPair()
        val rsaKey: RSAKey =
            RSAKey
                .Builder(keyPair.public as RSAPublicKey)
                .privateKey(keyPair.private as RSAPrivateKey)
                .keyID(UUID.randomUUID().toString())
                .build()
        return ImmutableJWKSet(JWKSet(rsaKey))
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder = OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings = AuthorizationServerSettings.builder().build()
}
