package com.zxytech.example.crypto.controller;

import com.zxytech.crypto.starter.annotation.DecryptRequest;
import com.zxytech.crypto.starter.annotation.EncryptResponse;
import com.zxytech.example.crypto.domain.User;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/crypto")
@EncryptResponse
public class CryptoController {

    @RequestMapping("/str")
    public String getStr(String name) {
        return name != null ? String.format("Hello %s", name) : "Hello World";
    }

    @PostMapping("/user")
    public User getUser(@RequestBody User user) {
        return user != null ? user : User.builder().name("anonymous").age(18).build();
    }


    @PostMapping("/encrypt/str")
    @DecryptRequest
    public String getEncryptStr(@RequestBody String name) {
        return name != null ? String.format("Hello %s", name) : "Hello World";
    }

    @PostMapping("/encrypt/user")
    @DecryptRequest
    public User getEncryptUser(@RequestBody User user) {
        return user != null ? user : User.builder().name("anonymous").age(18).build();
    }
}
