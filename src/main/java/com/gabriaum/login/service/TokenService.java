package com.gabriaum.login.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.gabriaum.login.model.UserModel;
import com.gabriaum.login.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class TokenService {

    @Value("${api.security.token.secret}")
    private String secret;

    private final UserRepository repository;

    public String generateToken(UserModel user) {
        return JWT.create()
                .withIssuer("gabriaum_login-crud-spring")
                .withSubject(user.getEmail())
                .withExpiresAt(new Date(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(1)))
                .sign(Algorithm.HMAC256(secret));
    }

    public boolean checkToken(UserModel user, String token) {
        try {
            String subject = JWT.require(Algorithm.HMAC256(secret))
                    .withIssuer("gabriaum_login-crud-spring")
                    .build()
                    .verify(token)
                    .getSubject();
            return subject.equals(user.getEmail());
        } catch (Exception ex)  {
            ex.printStackTrace();
        }

        return false;
    }

    public boolean validateToken(String token) {
        try {
            JWT.require(Algorithm.HMAC256(secret))
                    .withIssuer("gabriaum_login-crud-spring")
                    .build()
                    .verify(token);
            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return false;
    }

    public String getSubject(String token) {
        return JWT.require(Algorithm.HMAC256(secret))
                .withIssuer("gabriaum_login-crud-spring")
                .build()
                .verify(token)
                .getSubject();
    }

    public UsernamePasswordAuthenticationToken getAuthentication(String token) {
        String userEmail = JWT.require(Algorithm.HMAC256(secret))
                .withIssuer("gabriaum_login-crud-spring")
                .build()
                .verify(token)
                .getSubject();
        UserModel user = repository.findByEmail(userEmail).orElseThrow();
        return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
    }

    public UserModel getUserDetails(String token) {
        String userEmail = JWT.require(Algorithm.HMAC256(secret))
                .withIssuer("gabriaum_login-crud-spring")
                .build()
                .verify(token)
                .getSubject();
        return repository.findByEmail(userEmail).orElseThrow();
    }
}