package com.amir.security.auth

import lombok.AllArgsConstructor
import lombok.Builder
import lombok.Data
import lombok.NoArgsConstructor

data class AuthenticationRequest(
    val email: String,
    val password: String
)
