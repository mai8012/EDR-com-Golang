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
	ServerURL    = "http://192.168.2.101:7777/api/suspects"
	pingURL      = "http://192.168.2.101:7777/api/ping" // Altere conforme necessário
	pingInterval = 10 * time.Second                     //Envia pings periódicos para o servidor para indicar que o agente está online.

)

// sendPings envia pings periódicos para o servidor para indicar que o agente está online
func SendPings(agentID string, stopChan <-chan os.Signal) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Preparar o payload do ping
			payload := map[string]string{
				"id": agentID,
			}
			jsonData, err := json.Marshal(payload)
			if err != nil {
				log.Printf("Erro ao serializar JSON para ping: %v", err)
				continue
			}

			// Enviar o ping
			resp, err := client.Post(pingURL, "application/json", bytes.NewBuffer(jsonData))
			if err != nil {
				log.Printf("Erro ao enviar ping: %v", err)
				continue
			}

			// Ler e descartar o corpo da resposta
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
