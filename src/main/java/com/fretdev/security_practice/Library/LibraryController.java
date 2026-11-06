package com.fretdev.security_practice.Library;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LibraryController {
    @GetMapping("/hello")
    String hello(Authentication authentication){
        return "Hello" + authentication.getName() + " " + authentication.getAuthorities();
    }

    @GetMapping("/admin/dashboard")
    String adminDashboard(Authentication authentication){
        return "AdminDashboard" + authentication.getName();
    }
}