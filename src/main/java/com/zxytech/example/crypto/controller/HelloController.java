package com.zxytech.example.crypto.controller;

import com.zxytech.example.crypto.domain.User;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/hello")
public class HelloController {

    @RequestMapping("/str")
    public String getStr(String name) {
        return name != null ? String.format("Hello %s", name) : "Hello World";
    }

    @PostMapping("/user")
    public User getUser(@RequestBody User user) {
        return user != null ? user : User.builder().name("anonymous").age(18).build();
    }
}
