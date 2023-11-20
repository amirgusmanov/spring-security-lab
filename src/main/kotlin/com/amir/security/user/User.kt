package com.amir.security.user

import jakarta.persistence.*
import lombok.AllArgsConstructor
import lombok.Builder
import lombok.NoArgsConstructor
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "_user")
data class User(
    @Id @GeneratedValue private val id: Int = 0,
    private val firstName: String,
    private val lastName: String,
    private val email: String,
    private val password: String,
    @Enumerated(EnumType.STRING) private  val role: Role
) : UserDetails {

    override fun getAuthorities(): MutableCollection<out GrantedAuthority> = mutableListOf(
        SimpleGrantedAuthority(role.name)
    )

    override fun getPassword(): String = password

    override fun getUsername(): String = email

    override fun isAccountNonExpired(): Boolean = true

    override fun isAccountNonLocked(): Boolean = true

    override fun isCredentialsNonExpired(): Boolean = true

    override fun isEnabled(): Boolean = true
}
