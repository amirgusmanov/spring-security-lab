package com.amir.security.config

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import lombok.RequiredArgsConstructor
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

private const val AUTHORIZATION = "Authorization"
private const val BEARER = "Bearer "

@Component
@RequiredArgsConstructor
class JwtAuthenticationFilter(
    private val jwtService: JwtService,
    private val userDetailsService: UserDetailsService
) : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val authHeader: String? = request.getHeader(AUTHORIZATION)
        if (authHeader == null || !authHeader.startsWith(BEARER)) filterChain.doFilter(request, response)

        val jwt: String? = authHeader?.substring(BEARER.length)
        val userEmail: String? = jwtService.extractUsername(jwt)

        if (userEmail.isNullOrBlank() && SecurityContextHolder.getContext().authentication == null) {
            val userDetails: UserDetails = this.userDetailsService.loadUserByUsername(userEmail)
            if (jwt != null && jwtService.isTokenValid(jwt, userDetails)) {
                SecurityContextHolder.getContext().authentication = UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.authorities
                ).apply {
                    details = WebAuthenticationDetailsSource().buildDetails(request)
                }
            }
        }

        filterChain.doFilter(request, response)
    }
}