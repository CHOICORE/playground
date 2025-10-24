package me.choicore.projects.session

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.beans.factory.BeanClassLoaderAware
import org.springframework.boot.jackson.JsonMixin
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer
import org.springframework.data.redis.serializer.RedisSerializer
import org.springframework.security.jackson2.SecurityJackson2Modules

@Configuration(proxyBeanMethods = false)
class SessionConfiguration : BeanClassLoaderAware {
    private lateinit var classLoader: ClassLoader

    @Bean
    fun springSessionDefaultRedisSerializer(objectMapper: ObjectMapper): RedisSerializer<*> {
        val copied = objectMapper.copy()
        copied.registerModules(SecurityJackson2Modules.getModules(this.classLoader))
        return GenericJackson2JsonRedisSerializer(copied)
    }

    override fun setBeanClassLoader(classLoader: ClassLoader) {
        this.classLoader = classLoader
    }

    @JsonMixin(java.lang.Long::class, Long::class)
    internal abstract class LongMixin
}
