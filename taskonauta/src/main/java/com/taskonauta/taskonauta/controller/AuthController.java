package com.taskonauta.taskonauta.controller;

import java.util.Map;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.taskonauta.taskonauta.model.UserModel;
import com.taskonauta.taskonauta.security.JwtUtil;
import com.taskonauta.taskonauta.service.UserService;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> request) {
        System.out.println("Received registration request: " + request);

        try {
            String username = request.get("username");
            String email = request.get("email");
            String password = request.get("password");

            if (username == null || username.isBlank() ||
                    email == null || email.isBlank() ||
                    password == null || password.isBlank()) {
                return ResponseEntity
                        .badRequest()
                        .body(Map.of("error", "All fields (username, email, password) are required"));
            }
            if (!email.matches("^[\\w\\.-]+@[\\w\\.-]+\\.[a-zA-Z]{2,}$")) {
                return ResponseEntity
                        .badRequest()
                        .body(Map.of("error", "Invalid email format"));
            }
            if (password.length() < 8) {
                return ResponseEntity
                        .status(HttpStatus.UNPROCESSABLE_ENTITY)
                        .body(Map.of("error", "Password must be at least 8 characters long"));
            }

            if (userService.existsByEmail(email)) {
                return ResponseEntity
                        .status(HttpStatus.CONFLICT)
                        .body(Map.of("error", "Email already registered"));
            }

            UserModel user = userService.register(username, email, password);

            return ResponseEntity
                    .status(HttpStatus.CREATED)
                    .body(Map.of(
                            "id", user.getId(),
                            "username", user.getUsername(),
                            "email", user.getEmail()));

        } catch (SecurityException e) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Unauthorized action: " + e.getMessage()));

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Internal server error", "details", e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> request) {
        System.out.println("Received login request: " + request);

        try {
            String email = request.get("email");
            String password = request.get("password");

            if (email == null || email.isBlank() || password == null || password.isBlank()) {
                return ResponseEntity
                        .badRequest()
                        .body(Map.of("error", "Email and password are required"));
            }

            if (!email.matches("^[\\w\\.-]+@[\\w\\.-]+\\.[a-zA-Z]{2,}$")) {
                return ResponseEntity
                        .badRequest()
                        .body(Map.of("error", "Invalid email format"));
            }

            Optional<UserModel> userOpt = userService.findByEmail(email);
            if (userOpt.isEmpty()) {
                return ResponseEntity
                        .status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Invalid email or password"));
            }

            UserModel user = userOpt.get();

            String token = JwtUtil.generateToken(user.getEmail());

            return ResponseEntity.ok(Map.of(
                    "message", "Login successful",
                    "token", token, 
                    "user", Map.of(
                            "id", user.getId(),
                            "username", user.getUsername(),
                            "email", user.getEmail())));

        } catch (SecurityException e) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Unauthorized action: " + e.getMessage()));

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Internal server error", "details", e.getMessage()));
        }
    }

}
