package me.choicore.projects.security

import org.springframework.boot.autoconfigure.security.SecurityProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.session.SessionRegistry
import org.springframework.security.core.session.SessionRegistryImpl
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.session.HttpSessionEventPublisher

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class WebSecurityConfiguration {
    @Bean
    fun defaultSecurityFilterChain(httpSecurity: HttpSecurity): SecurityFilterChain {
        httpSecurity
            .authorizeHttpRequests {
                it.anyRequest().authenticated()
            }.formLogin {
                it.loginPage("/sign-in").permitAll()
                it.loginProcessingUrl("/sign-in")
            }

        return httpSecurity.build()
    }

    @Bean
    fun userDetailsService(securityProperties: SecurityProperties): UserDetailsService {
        val user = securityProperties.user

        val userDetails =
            User
                .withUsername(user.name)
                .password("{noop}${user.password}")
                .roles(*user.roles.toTypedArray())
                .build()

        return InMemoryUserDetailsManager(userDetails)
    }

    @Bean
    fun sessionRegistry(): SessionRegistry = SessionRegistryImpl()

    @Bean
    fun httpSessionEventPublisher(): HttpSessionEventPublisher = HttpSessionEventPublisher()
}
