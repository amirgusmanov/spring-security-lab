package com.amir.security.auth

import lombok.AllArgsConstructor
import lombok.NoArgsConstructor

@AllArgsConstructor
@NoArgsConstructor
data class AuthenticationResponse(private val token: String)