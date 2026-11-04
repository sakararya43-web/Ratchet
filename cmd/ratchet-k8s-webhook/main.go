package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/sakararya43-web/Ratchet/internal/connector/k8s"
)

type WebhookServer struct {
	handler *k8s.AdmissionWebhookHandler
}

func NewWebhookServer() *WebhookServer {
	return &WebhookServer{
		handler: k8s.NewAdmissionWebhookHandler(),
	}
}

func (s *WebhookServer) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("POST /validate", s.handleValidate)
	mux.HandleFunc("POST /api/v1/intent", s.handleRegisterIntent)
	return mux
}

func (s *WebhookServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "ratchet-k8s-webhook",
	})
}

func (s *WebhookServer) handleValidate(w http.ResponseWriter, r *http.Request) {
	var review k8s.AdmissionReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		http.Error(w, fmt.Sprintf("invalid admission review: %v", err), http.StatusBadRequest)
		return
	}

	if review.Request == nil {
		http.Error(w, "missing request in admission review", http.StatusBadRequest)
		return
	}

	admResp := s.handler.HandleAdmission(review.Request)

	respReview := k8s.AdmissionReview{
		APIVersion: review.APIVersion,
		Kind:       review.Kind,
		Response:   admResp,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(respReview)
}

func (s *WebhookServer) handleRegisterIntent(w http.ResponseWriter, r *http.Request) {
	var intent k8s.ApprovedIntent
	if err := json.NewDecoder(r.Body).Decode(&intent); err != nil {
		http.Error(w, fmt.Sprintf("invalid intent payload: %v", err), http.StatusBadRequest)
		return
	}

	s.handler.RegisterIntent(&intent)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "registered",
		"intent_id": intent.IntentID,
	})
}

func main() {
	port := flag.Int("port", 8443, "Webhook server port")
	flag.Parse()

	server := NewWebhookServer()
	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Starting ratchet-k8s-webhook on %s", addr)
	if err := http.ListenAndServe(addr, server.Routes()); err != nil {
		log.Fatalf("webhook server failed: %v", err)
	}
}
