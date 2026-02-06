package com.owuor.airbnbclone;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.Date;

@SpringBootApplication
public class AirbnbcloneApplication {

	public static void main(String[] args) {
		SpringApplication.run(AirbnbcloneApplication.class, args);
		System.out.println("AIRBNBCLONE APPLICATION STARTED ON PORT 8081 AT " + new Date());
	}

}
