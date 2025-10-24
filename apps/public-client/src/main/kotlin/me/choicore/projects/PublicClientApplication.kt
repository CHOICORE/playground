package me.choicore.projects

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class PublicClientApplication

fun main(args: Array<String>) {
    runApplication<PublicClientApplication>(*args)
}
