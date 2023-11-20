package com.amir.security.auth

import com.amir.security.config.JwtService
import com.amir.security.user.Role
import com.amir.security.user.User
import com.amir.security.user.UserRepository
import lombok.RequiredArgsConstructor
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

private const val USER_NOT_FOUND_MSG = "User not found"

@Service
@RequiredArgsConstructor
class AuthenticationService(
    private val repository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jwtService: JwtService,
    private val authenticationManager: AuthenticationManager
) {

    fun register(request: RegisterRequest): AuthenticationResponse? {
        val user = User(
            firstName = request.firstName,
            lastName = request.secondName,
            email = request.email,
            password = passwordEncoder.encode(request.password),
            role = Role.USER
        ).also { repository.save(it) }
        return AuthenticationResponse(token = jwtService.generateToken(user))
    }

    fun authenticate(request: AuthenticationRequest): AuthenticationResponse? {
        authenticationManager.authenticate(UsernamePasswordAuthenticationToken(request.email, request.password))
        val user = repository.findByEmail(request.email) ?: throw UsernameNotFoundException(USER_NOT_FOUND_MSG)
        return AuthenticationResponse(token = jwtService.generateToken(user))
    }
}