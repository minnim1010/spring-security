package com.example.formlogin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(scanBasePackages ={"com.example.database", "com.example.formlogin"})
@EntityScan(basePackages = {"com.example.database"})
@EnableJpaRepositories(basePackages = {"com.example.database"})
public class FormloginApplication {

    public static void main(String[] args) {
        SpringApplication.run(FormloginApplication.class, args);
    }

}
