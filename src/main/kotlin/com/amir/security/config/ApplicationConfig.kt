package com.amir.security.config

import com.amir.security.user.UserRepository
import lombok.RequiredArgsConstructor
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder

private const val USER_NOT_FOUND_MSG = "User not found"

@Configuration
@RequiredArgsConstructor
class ApplicationConfig(private val repository: UserRepository) {

    @Bean
    fun userDetailsService(): UserDetailsService = UserDetailsService { username ->
        repository.findByEmail(username) ?: throw UsernameNotFoundException(USER_NOT_FOUND_MSG)
    }

    @Bean
    fun authenticationProvider(): AuthenticationProvider = DaoAuthenticationProvider().apply {
        setUserDetailsService(userDetailsService())
        setPasswordEncoder(passwordEncoder())
    }

    @Bean
    fun authenticationManager(config: AuthenticationConfiguration): AuthenticationManager = config.authenticationManager

    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()
}