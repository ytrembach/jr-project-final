package com.javarush.jira.login.internal.jwt.dto;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class SignUpRequest {

    @Size(max = 32)
    @Nullable
    String displayName;

    @Email
    @Size(max = 128)
    @NotBlank
    private String email;


    @Size(min = 5, max = 128)
    @NotBlank
    private String password;

    @NotBlank
    @Size(min = 2, max = 32)
    private String firstName;

    @NotBlank
    @Size(min = 2, max = 32)
    private String lastName;

}