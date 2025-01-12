package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"edr-agent/addtask"
	"edr-agent/monitor"
	"edr-agent/ping"

	"github.com/google/uuid"                    // Geração e manipulação de identificadores únicos para o Agente.
	psutil "github.com/shirou/gopsutil/process" // Obtenção e manipulação de informações sobre processos em execução no sistema.
)

const (
	// Intervalo
	fetchInterval = 15 * time.Second // Gerencia o envio de suspeitas e a busca de decisões via HTTP
)

var (
	// Mapa para mapear IDs de mensagens para processos suspeitos
	messageIDToProcess     = make(map[int]monitor.SuspiciousProcess)
	messageIDToProcessLock sync.Mutex

	// Fila para rastrear mensagens pendentes para deduplicação
	pendingResponses     = []int{}
	pendingResponsesLock sync.Mutex

	// Contador para IDs únicos
	suspectID     = 0
	suspectIDLock sync.Mutex
)

// Decision representa a resposta do servidor para uma suspeita.
type Decision struct {
	MessageID int    `json:"message_id"`
	Response  string `json:"response"` // "y" ou "n"
}

// SuspiciousProcess representa um processo suspeito detectado.
type SuspiciousProcess struct {
	Name string `json:"name"`
	Path string `json:"path"`
	PID  int    `json:"pid"`
	IPs  string `json:"ips"`
	Host string `json:"host"`
}

func main() {
	log.Println("Iniciando agente EDR (Windows)...")

	// addScheduledTask cria tarefa agendada para iniciar junto com o sistema com todos os usuarios
	// vai pedir senha do usuario admin que executou o agente
	// depois de criada a tarefa temos uma verificação para ver se a tarefa esta criada
	// então uma vez configurado não vai pedir novamente
	// e todo usuario que logar na maquina mesmo não sendo admin o agent vai startar com privilegios
	addtask.AddScheduledTask()

	// Identificador único do agente
	agentID := getAgentIdentifier()
	log.Printf("Identificador do Agente: %s", agentID)

	// Canais para comunicação
	suspicionsChan := make(chan monitor.SuspiciousProcess, 1000)
	decisionsChan := make(chan Decision, 1000)
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	// Goroutine para monitorar processos
	wg.Add(1)
	go func() {
		defer wg.Done()
		monitor.WatchProcesses(suspicionsChan)
	}()

	// Goroutine para processar decisões
	wg.Add(1)
	go func() {
		defer wg.Done()
		handleDecisions(decisionsChan)
	}()

	// Goroutine para gerenciar comunicação HTTP
	wg.Add(1)
	go func() {
		defer wg.Done()
		manageHTTPCommunication(ping.ServerURL, suspicionsChan, decisionsChan, stopChan)
	}()

	// Goroutine para enviar pings
	wg.Add(1)
	go func() {
		defer wg.Done()
		ping.SendPings(agentID, stopChan)
	}()

	// Aguarda sinal de interrupção
	<-stopChan
	log.Println("Encerrando agente EDR...")

	// Fechar os canais
	close(suspicionsChan)
	close(decisionsChan)

	wg.Wait()
}

// manageHTTPCommunication gerencia o envio de suspeitas e a busca de decisões via HTTP
func manageHTTPCommunication(
	serverURL string,
	suspicionsChan <-chan monitor.SuspiciousProcess,
	decisionsChan chan<- Decision,
	stopChan <-chan os.Signal,
) {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	ticker := time.NewTicker(fetchInterval)
	defer ticker.Stop()

	for {
		select {
		case suspect, ok := <-suspicionsChan:
			if !ok {
				return
			}

			// Enviar suspeita ao servidor
			messageID := getNextMessageID()
			reqBody := map[string]interface{}{
				"id":      messageID,
				"message": formatSuspectMessage(suspect),
				"agent":   getAgentIdentifier(),
			}
			jsonData, err := json.Marshal(reqBody)
			if err != nil {
				log.Printf("Erro ao serializar JSON: %v", err)
				continue
			}

			resp, err := client.Post(serverURL, "application/json", bytes.NewBuffer(jsonData))
			if err != nil {
				log.Printf("Erro ao enviar suspeita: %v", err)
				continue
			}

			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusAccepted {
				log.Printf("Servidor retornou status %d: %s", resp.StatusCode, string(body))
				continue
			}

			var respData map[string]int
			if err := json.Unmarshal(body, &respData); err != nil {
				log.Printf("Erro ao decodificar resposta: %v", err)
				continue
			}

			receivedID, exists := respData["id"]
			if !exists {
				log.Printf("Resposta inválida do servidor: %s", string(body))
				continue
			}

			messageIDToProcessLock.Lock()
			messageIDToProcess[receivedID] = suspect
			messageIDToProcessLock.Unlock()

			pendingResponsesLock.Lock()
			pendingResponses = append(pendingResponses, receivedID)
			pendingResponsesLock.Unlock()

			log.Printf("Suspeita enviada com ID %d", receivedID)

		case <-ticker.C:
			// Buscar respostas do servidor
			fetchResponses(client, serverURL, decisionsChan)

		case <-stopChan:
			return
		}
	}
}

// fetchResponses busca respostas do servidor para as suspeitas pendentes
func fetchResponses(client *http.Client, serverURL string, decisionsChan chan<- Decision) {
	pendingResponsesLock.Lock()
	if len(pendingResponses) == 0 {
		pendingResponsesLock.Unlock()
		return
	}

	// Monta a query de IDs pendentes
	ids := ""
	for i, id := range pendingResponses {
		if i > 0 {
			ids += ","
		}
		ids += fmt.Sprintf("%d", id)
	}
	pendingResponsesLock.Unlock()

	reqURL := fmt.Sprintf("%s/responses?ids=%s", serverURL, ids)
	resp, err := client.Get(reqURL)
	if err != nil {
		log.Printf("Erro ao buscar respostas: %v", err)
		// Caso ocorra erro na busca, enviar "n" para todos IDs pendentes
		pendingResponsesLock.Lock()
		for _, id := range pendingResponses {
			decisionsChan <- Decision{MessageID: id, Response: "n"}
		}
		pendingResponses = nil
		pendingResponsesLock.Unlock()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Erro ao buscar respostas, status: %d", resp.StatusCode)
		// Em caso de status != 200, também enviar "n" para todos IDs pendentes
		pendingResponsesLock.Lock()
		for _, id := range pendingResponses {
			decisionsChan <- Decision{MessageID: id, Response: "n"}
		}
		pendingResponses = nil
		pendingResponsesLock.Unlock()
		return
	}

	var decisions []Decision
	if err := json.NewDecoder(resp.Body).Decode(&decisions); err != nil {
		log.Printf("Erro ao decodificar respostas: %v", err)
		// Se falhar o decode, novamente "n" para todos IDs pendentes
		pendingResponsesLock.Lock()
		for _, id := range pendingResponses {
			decisionsChan <- Decision{MessageID: id, Response: "n"}
		}
		pendingResponses = nil
		pendingResponsesLock.Unlock()
		return
	}

	for _, decision := range decisions {
		decisionsChan <- decision

		// Remove o ID da lista de pendentes
		pendingResponsesLock.Lock()
		for i, id := range pendingResponses {
			if id == decision.MessageID {
				pendingResponses = append(pendingResponses[:i], pendingResponses[i+1:]...)
				break
			}
		}
		pendingResponsesLock.Unlock()
	}
}

// handleDecisions processa as decisões recebidas do servidor.
func handleDecisions(decisionsChan <-chan Decision) {
	for decision := range decisionsChan {
		// Obtém o processo suspeito associado ao ID
		messageIDToProcessLock.Lock()
		suspect, exists := messageIDToProcess[decision.MessageID]
		if !exists {
			log.Printf("[AVISO] Decisão recebida para ID desconhecido: %d", decision.MessageID)
			messageIDToProcessLock.Unlock()
			continue
		}
		delete(messageIDToProcess, decision.MessageID)
		messageIDToProcessLock.Unlock()

		// Executa a ação baseada na resposta
		if decision.Response == "y" {
			// Resposta 'y': Retoma o processo
			err := monitor.ResumeProcess(suspect.PID)
			if err != nil {
				log.Printf("[ERRO] ao retomar processo PID %d: %v", suspect.PID, err)
			} else {
				log.Printf("[LIBERADO] Processo %s (PID=%d) retomado com sucesso.\n", suspect.Path, suspect.PID)
			}
		} else if decision.Response == "n" {
			// Resposta 'n': Finaliza o processo
			p, err := psutil.NewProcess(int32(suspect.PID))
			if err != nil {
				log.Printf("[ERRO] ao obter processo PID %d: %v", suspect.PID, err)
			} else {
				if errKill := p.Kill(); errKill != nil {
					log.Printf("[ERRO] Não foi possível finalizar o PID %d: %v", suspect.PID, errKill)
				} else {
					log.Printf("[FINALIZADO] Processo %s (PID=%d) foi finalizado.\n", suspect.Path, suspect.PID)
				}
			}
		}
	}
}

// getNextMessageID gera um ID único para cada mensagem enviada.
func getNextMessageID() int {
	suspectIDLock.Lock()
	defer suspectIDLock.Unlock()
	suspectID++
	return suspectID
}

// formatSuspectMessage formata a mensagem suspeita no formato esperado pelo servidor
func formatSuspectMessage(suspect monitor.SuspiciousProcess) string {
	return fmt.Sprintf(
		"[SUSPEITO] Name:%s|Path:%s|PID:%d|IP:%s|Host:%s",
		suspect.Name,
		suspect.Path,
		suspect.PID,
		suspect.IPs,
		suspect.Host,
	)
}

// getAgentIdentifier retorna uma identificação única para o agente
func getAgentIdentifier() string {
	hostname, err := os.Hostname()
	if err != nil {
		log.Println("Erro ao obter hostname, gerando UUID")
		return uuid.New().String()
	}
	return hostname
}
