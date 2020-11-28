package com.zxytech.example.crypto;

import com.zxytech.crypto.starter.annotation.EnableSecurity;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@EnableSecurity
@SpringBootApplication
public class CryptoStarterExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(CryptoStarterExampleApplication.class, args);
    }

}
