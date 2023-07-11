package io.samtech.security.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
// todo-> to hide the Controller use @Hidden on the controller class
@RestController
@RequestMapping("/api/v1/auth/demo")
public class DemoController {

    @GetMapping
    public ResponseEntity<String> sayHello(){
        return ResponseEntity.ok("Hello from Secured Endpoint");
    }
}
