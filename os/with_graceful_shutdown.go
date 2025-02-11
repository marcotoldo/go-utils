package os

import (
	"os"
	"os/signal"
	"syscall"
)

// intercept graceful shutdown requests (Ctrl+C, and graceful shutdown request from docker,kubernetes)
// Useful for closing any connection (db, messaging, ...) before exit
func WithGracefulShutdown(cb func(), onExit func()) {
	// Create a channel to listen for OS signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	defer onExit()

	cb()

	<-stop
}
