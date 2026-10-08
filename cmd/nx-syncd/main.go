package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"nx-sync-server/internal/config"
	"nx-sync-server/internal/daemon"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	configPath := flag.String("config", "/etc/nx-syncd/config.json", "configuration file")
	version := flag.Bool("version", false, "print version")
	flag.Parse()
	if *version {
		fmt.Println(config.Version)
		return
	}
	logger := log.New(os.Stderr, "nx-syncd: ", log.LstdFlags)
	if os.Geteuid() == 0 {
		logger.Print("refusing to run as root; use the unprivileged service account")
		os.Exit(1)
	}
	c, err := config.Load(*configPath)
	if err != nil {
		logger.Print("invalid configuration")
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err = daemon.Run(ctx, c, logger); err != nil {
		logger.Print("startup or shutdown failed; inspect local configuration and storage")
		os.Exit(1)
	}
}
