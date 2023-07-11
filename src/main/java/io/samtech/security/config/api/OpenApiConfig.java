package io.samtech.security.config.api;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;

@OpenAPIDefinition(
        info = @Info(
                contact = @Contact(
                        name = "SamTech",
                        email = "fanusamuel@gmail.com",
                        url = "http"
                ),
                description = "OpenApi Documentation for Spring Security",
                title = "OpenApi Specification - SamTech",
                version = "1.0",
                license = @License(
                        name = "Semicolon Africa Trainee",
                        url = "https:semicolon.africa.com"
                ),
                termsOfService = "Your Are The Handicap You Must Face"
        ),
        servers = {
                @Server(
                        description = "Local ENV",
                        url = "http://localhost:8080"
                ),
                @Server(
                        description = "PROD ENV",
                        url = "http://localhost:5252"
                )
        },
        security = {
                @SecurityRequirement(
                        name = "bearerAuth"
                )
        }



)
@SecurityScheme(
        name = "bearerAuth",
        description = "JWT auth description",
        scheme = "bearer",
        type = SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        in = SecuritySchemeIn.HEADER
)
public class OpenApiConfig {
}
