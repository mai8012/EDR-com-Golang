package ping

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	// Endpoints e Intervalos
	ServerURL    = "http://192.168.2.100:7777/api/suspects"
	pingURL      = "http://192.168.2.100:7777/api/ping" // Altere conforme necessário
	pingInterval = 10 * time.Second
)

func SendPings(agentID string, stopChan <-chan os.Signal) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			payload := map[string]string{
				"id": agentID,
			}
			jsonData, err := json.Marshal(payload)
			if err != nil {
				log.Printf("Erro ao serializar JSON para ping: %v", err)
				continue
			}

			resp, err := client.Post(pingURL, "application/json", bytes.NewBuffer(jsonData))
			if err != nil {
				log.Printf("Erro ao enviar ping: %v", err)
				continue
			}

			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				log.Printf("Servidor retornou status %d para ping", resp.StatusCode)
				continue
			}

			log.Println("Ping enviado com sucesso")

		case <-stopChan:
			log.Println("Encerrando envio de pings")
			return
		}
	}
}
