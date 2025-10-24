package me.choicore.projects.authorization

import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping

@Controller
class IndexController {
    @GetMapping("/", "/index")
    fun root(): String = "/index"

    @GetMapping("/exception")
    fun exception(model: Model): String = throw RuntimeException("exception")
}
