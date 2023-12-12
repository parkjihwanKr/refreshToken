package com.pjh.refreshtoken;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/")
    public String showHomePage(){
        return "index";
    }

    @GetMapping("/auth/signup")
    public String showSignupPage(){
        return "signup";
    }
}
