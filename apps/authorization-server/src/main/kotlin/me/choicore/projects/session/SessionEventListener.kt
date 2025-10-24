package me.choicore.projects.session

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.context.event.EventListener
import org.springframework.session.events.SessionCreatedEvent
import org.springframework.session.events.SessionDeletedEvent
import org.springframework.session.events.SessionDestroyedEvent
import org.springframework.session.events.SessionExpiredEvent
import org.springframework.stereotype.Component

@Component
class SessionEventListener {
    @EventListener
    fun processSessionCreatedEvent(event: SessionCreatedEvent) {
        // do the necessary work
        log.info("Session Created: ${event.sessionId}")
    }

    @EventListener
    fun processSessionDeletedEvent(event: SessionDeletedEvent) {
        // do the necessary work
        log.info("Session Deleted: ${event.sessionId}")
    }

    @EventListener
    fun processSessionDestroyedEvent(event: SessionDestroyedEvent) {
        // do the necessary work
        log.info("Session Destroyed: ${event.sessionId}")
    }

    @EventListener
    fun processSessionExpiredEvent(event: SessionExpiredEvent) {
        // do the necessary work
        log.info("Session Expired: ${event.sessionId}")
    }

    companion object {
        private val log: Logger = LoggerFactory.getLogger(SessionEventListener::class.java)
    }
}
