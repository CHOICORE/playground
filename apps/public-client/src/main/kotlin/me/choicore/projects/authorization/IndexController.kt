package me.choicore.projects.authorization

import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping

@Controller
class IndexController {
    @GetMapping("/")
    fun root(): String = "redirect:/index"

    @GetMapping("/index")
    fun index(): String = "index"
}
