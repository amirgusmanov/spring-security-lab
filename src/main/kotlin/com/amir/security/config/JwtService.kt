package com.amir.security.config

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service
import java.security.Key
import java.util.*
import kotlin.collections.HashMap

@Service
class JwtService {

    companion object {
        private const val SECRET_KEY = "9589d710740380bda78ae7582f1b845548ca525289bd3f1d0250efd91b34a934"
    }

    fun extractUsername(token: String?): String? = token?.let {
        extractClaim(token = it, claimsResolver = Claims::getSubject)
    }

    fun <T> extractClaim(token: String, claimsResolver: (Claims) -> T) : T {
        val claims = extractAllClaims(token)
        return claimsResolver.invoke(claims)
    }

    fun generateToken(userDetails: UserDetails): String = generateToken(HashMap(), userDetails)

    fun isTokenValid(token: String, userDetails: UserDetails): Boolean {
        val username: String? = extractUsername(token)
        return username == userDetails.username && !isTokenExpired(token)
    }

    fun generateToken(extraClaims: Map<String, Any>, userDetails: UserDetails): String = Jwts
        .builder()
        .setClaims(extraClaims)
        .setSubject(userDetails.username)
        .setIssuedAt(Date(System.currentTimeMillis()))
        .setExpiration(Date(System.currentTimeMillis() + 1000 * 60 * 24))
        .signWith(getSignInKey(), SignatureAlgorithm.HS256)
        .compact()

    private fun isTokenExpired(token: String): Boolean = extractExpiration(token).before(Date())

    private fun extractExpiration(token: String): Date = extractClaim(token, Claims::getExpiration)

    private fun extractAllClaims(token: String): Claims = Jwts
        .parser()
        .setSigningKey(getSignInKey())
        .build()
        .parseClaimsJws(token)
        .body

    private fun getSignInKey(): Key {
        val keyBytes = Decoders.BASE64.decode(SECRET_KEY)
        return Keys.hmacShaKeyFor(keyBytes)
    }
}
