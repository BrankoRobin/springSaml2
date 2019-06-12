package com.callsign.saml.controller;

import com.callsign.saml.config.CustomAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpSession;

@Controller
@RequestMapping("/")
public class LoginController {

    @Autowired
    CustomAuthenticationProvider authenticationManager;

    @GetMapping("/hello")
    public String home(Model model, @RequestParam(value = "name", required = false, defaultValue = "World") String name) {
        model.addAttribute("name", name);
        return "hello";
    }

    @GetMapping("/login")
    public String home() {
        return "login";
    }

    @RequestMapping(value="/loginSecure", method = RequestMethod.POST)
    public String login(@RequestAttribute("username") String userName) {

        //does the authentication
        final Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        userName,
                        "branko"
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return "hello";
    }
}
