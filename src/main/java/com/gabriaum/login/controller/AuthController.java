package com.gabriaum.login.controller;

import com.gabriaum.login.dto.LoginDTO;
import com.gabriaum.login.dto.RegisterDTO;
import com.gabriaum.login.model.UserModel;
import com.gabriaum.login.repository.UserRepository;
import com.gabriaum.login.service.EncryptService;
import com.gabriaum.login.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository repository;
    private final EncryptService encryptService;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginDTO dto) {
        if (!repository.existsById(dto.email()))
            return ResponseEntity.status(401).build();

        UserModel user = repository.findById(dto.email()).orElse(null);
        if (user != null) {
            if (encryptService.check(dto.password(), user.getPassword())) {
                String token = tokenService.generateToken(user);
                return ResponseEntity.ok(token);
            }
        }

        return ResponseEntity.badRequest().build();
    }

    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterDTO dto) {
        if (repository.existsById(dto.email()))
            return ResponseEntity.status(409).build();

        String encryptedPassword = encryptService.encrypt(dto.password());
        UserModel user = new UserModel(dto.email(), dto.username(), dto.email(), encryptedPassword);
        repository.save(user);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/validate")
    public ResponseEntity validateToken(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer "))
            return ResponseEntity.status(401).body("Missing or malformed token");

        String token = authHeader.substring(7).trim();
        try {
            boolean valid = tokenService.validateToken(token);
            return valid ? ResponseEntity.ok("Valid token") : ResponseEntity.status(401).body("Invalid token");
        } catch (Exception ex) {
            return ResponseEntity.status(401).body("Invalid or expired token");
        }
    }
}