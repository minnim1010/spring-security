package com.example.restjwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(scanBasePackages ={"com.example.database", "com.example.restjwt"})
@EntityScan(basePackages = {"com.example.database"})
@EnableJpaRepositories(basePackages = {"com.example.database"})
public class RestJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(RestJwtApplication.class, args);
    }

}
