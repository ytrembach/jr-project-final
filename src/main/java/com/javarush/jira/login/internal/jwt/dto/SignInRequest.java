package com.javarush.jira.login.internal.jwt.dto;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class SignInRequest {
    @Email
    @Size(max = 128)
    @NotBlank
    private String email;

    @Size(min = 5, max = 128)
    @NotBlank
    private String password;
}