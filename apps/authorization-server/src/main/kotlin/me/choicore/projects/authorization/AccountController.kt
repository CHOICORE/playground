package me.choicore.projects.authorization

import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping

@Controller
class AccountController {
    @GetMapping("/sign-in")
    fun signIn(model: Model): String = "account/sign-in"

    @GetMapping("/sign-up")
    fun signUp(model: Model): String = "account/sign-up"
}
