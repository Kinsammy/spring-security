package io.samtech.security;

import io.samtech.security.data.dto.request.RegisterRequest;
import io.samtech.security.exception.UserAlreadyExistException;
import io.samtech.security.service.AuthenticationService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static io.samtech.security.data.models.user.Role.ADMIN;
import static io.samtech.security.data.models.user.Role.MANAGER;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(
			AuthenticationService service
	) {
		return args -> {
			var admin = RegisterRequest.builder()
					.name("Admin")
					.email("admin@email.com")
					.password("password")
					.role(ADMIN)
					.build();
			System.out.printf("Admin token: %s%n", service.registerAdminAndManager(admin).getAccessToken());


			var manager = RegisterRequest.builder()
					.name("manager")
					.email("manager@email.com")
					.password("password")
					.role(MANAGER)
					.build();
			System.out.printf("Manager token: %s%n", service.registerAdminAndManager(manager).getAccessToken());
		};
	}

}
