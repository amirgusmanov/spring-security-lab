package com.amir.security.auth

import lombok.AllArgsConstructor
import lombok.Builder
import lombok.Data
import lombok.NoArgsConstructor

data class RegisterRequest(
    val firstName: String,
    val secondName: String,
    val email: String,
    val password: String,
)
