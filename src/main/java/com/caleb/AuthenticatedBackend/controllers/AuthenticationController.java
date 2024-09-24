package com.caleb.AuthenticatedBackend.controllers;

import com.caleb.AuthenticatedBackend.models.ApplicationUser;
import com.caleb.AuthenticatedBackend.models.LoginResponseDTo;
import com.caleb.AuthenticatedBackend.models.RegistrationDTO;
import com.caleb.AuthenticatedBackend.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@CrossOrigin("*")
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping( "/register")
    public ApplicationUser registerUser(@RequestBody RegistrationDTO body) {
        return authenticationService.registerUser(body.getUsername(), body.getPassword());
    }

    @PostMapping("/login")
    public LoginResponseDTo loginUser(@RequestBody RegistrationDTO body) {
        return authenticationService.loginUser(body.getUsername(), body.getPassword());
    }

}
