package me.choicore.projects.security

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesMapper
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(OAuth2ClientProperties::class)
class SecurityConfiguration {
    @Bean
    fun defaultSecurityFilterChain(httpSecurity: HttpSecurity): SecurityFilterChain {
        httpSecurity
            .authorizeHttpRequests {
                it.anyRequest().authenticated()
            }.oauth2Login {
                it.defaultSuccessUrl("/").successHandler(SimpleUrlAuthenticationSuccessHandler())
            }.oauth2Client(Customizer.withDefaults())

        return httpSecurity.build()
    }

    @Bean
    fun clientRegistrationRepository(oAuth2ClientProperties: OAuth2ClientProperties): InMemoryClientRegistrationRepository {
        val clientRegistrations =
            OAuth2ClientPropertiesMapper(oAuth2ClientProperties)
                .asClientRegistrations()
                .values
                .map {
                    ClientRegistration
                        .withClientRegistration(it)
                        .clientSettings(
                            ClientRegistration.ClientSettings
                                .builder()
                                .requireProofKey(true)
                                .build(),
                        ).build()
                }.toList()

        return InMemoryClientRegistrationRepository(clientRegistrations)
    }
}
