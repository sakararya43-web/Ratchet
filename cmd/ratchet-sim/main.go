package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/domain"
	"github.com/sakararya43-web/Ratchet/cmd/ratchet-sim/server"
)

func main() {
	port := flag.Int("port", 8085, "Simulator HTTP listen port")
	stateFile := flag.String("state", "sim_data.json", "Path to simulator state persistence file")
	brokerToken := flag.String("token", os.Getenv("SIM_BROKER_TOKEN"), "Broker authorization token")
	flag.Parse()

	store, err := domain.NewStore(*stateFile)
	if err != nil {
		log.Fatalf("failed to initialize simulator store: %v", err)
	}

	srv := server.NewServer(store, *brokerToken)
	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Starting ratchet-sim on %s (state file: %s)", addr, *stateFile)
	if err := http.ListenAndServe(addr, srv.Routes()); err != nil {
		log.Fatalf("simulator server failed: %v", err)
	}
}
