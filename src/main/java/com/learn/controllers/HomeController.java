package com.learn.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;


@Controller
public class HomeController {
    @GetMapping("/")
    String home(){
        return "login";
    }

    @GetMapping("/userPage")
//    @PreAuthorize("hasRole('ADMIN') || hasRole('USER') ")
    String userPage(){
        return "home";
    }
}
