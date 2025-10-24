package me.choicore.projects

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.task.TaskDecorator
import org.springframework.core.task.support.ContextPropagatingTaskDecorator
import org.springframework.scheduling.annotation.EnableAsync

@EnableAsync
@Configuration(proxyBeanMethods = false)
class AsyncConfiguration {
    @Bean
    fun contextPropagatingTaskDecorator(): TaskDecorator = ContextPropagatingTaskDecorator()
}
