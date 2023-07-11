package io.samtech.security.controller;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/admin")
@PreAuthorize("hasRole('ADMIN')")
//@SecurityRequirement(name = "bearerAuth")
public class AdminController {

//    To hide any endpoint
//    todo-> use @Hidden

    @GetMapping
    @PreAuthorize("hasAuthority('admin:read')")
    public String get(){
        return "GET:: admin controller";
    }

    @PostMapping
    @PreAuthorize("hasAuthority('admin:create')")
    public String post(){
        return "POST:: admin controller";
    }

    @PutMapping
    @PreAuthorize("hasAuthority('admin:put')")
    public String update(){
        return "PUT:: admin controller";
    }

    @DeleteMapping
    @PreAuthorize("hasAuthority('admin:delete')")
    public String delete(){
        return "DELETE:: admin controller";
    }
}
