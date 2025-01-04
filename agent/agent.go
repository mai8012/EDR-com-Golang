package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"edr-agent/monitor"

	"golang.org/x/term" //Manipulação avançada de terminais, útil para interações seguras com o usuário.

	"github.com/google/uuid"                    //Geração e manipulação de identificadores únicos para o Agente.
	psutil "github.com/shirou/gopsutil/process" //Obtenção e manipulação de informações sobre processos em execução no sistema.
)

const (
	// Endpoints e Intervalos
	serverURL      = "http://192.168.2.105:8080/api/suspects" // Altere para o endereço do seu servidor
	pingURL        = "http://192.168.2.105:8080/api/ping"     // Altere conforme necessário
	processScanInt = 10 * time.Second                         //"edr-agent/monitor"
	fetchInterval  = 15 * time.Second                         //Gerencia o envio de suspeitas e a busca de decisões via HTTP
	pingInterval   = 30 * time.Second                         //Envia pings periódicos para o servidor para indicar que o agente está online.

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

	//addScheduledTask cria tarefa agendada para iniciar junto com o sistema com todos os usuarios
	//vai pedir senha do usuario admin que deu start no agente
	//depois de criada a tarefa temos uma verificação para ver se a tarefa esta criada
	//então uma vez configurado não vai pedir novamente
	//e todo usuario que logar na maquina mesmo não sendo admin o agent vai startar com privilegios
	addScheduledTask()

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
		manageHTTPCommunication(serverURL, suspicionsChan, decisionsChan, stopChan)
	}()

	// Goroutine para enviar pings
	wg.Add(1)
	go func() {
		defer wg.Done()
		sendPings(agentID, stopChan)
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
func manageHTTPCommunication(serverURL string, suspicionsChan <-chan monitor.SuspiciousProcess, decisionsChan chan<- Decision, stopChan <-chan os.Signal) {
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

			// Se chegou até aqui, deu tudo certo.
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

	// Se chegou até aqui, temos respostas válidas do servidor
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

// sendPings envia pings periódicos para o servidor para indicar que o agente está online
func sendPings(agentID string, stopChan <-chan os.Signal) {
	client := &http.Client{
		Timeout: 30 * time.Second,
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

// getNextMessageID gera um ID único para cada mensagem enviada.
func getNextMessageID() int {
	suspectIDLock.Lock()
	defer suspectIDLock.Unlock()
	suspectID++
	return suspectID
}

// formatSuspectMessage formata a mensagem suspeita no formato esperado pelo servidor
func formatSuspectMessage(suspect monitor.SuspiciousProcess) string {
	return fmt.Sprintf("[SUSPEITO] Name:%s|Path:%s|PID:%d|IP:%s|Host:%s",
		suspect.Name, suspect.Path, suspect.PID, suspect.IPs, suspect.Host)
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

func addScheduledTask() {
	taskName := "SystemEDR" // Nome da tarefa agendada

	// 1. Verificar se a tarefa já existe
	if isTaskExists(taskName) {
		fmt.Println("A tarefa agendada já existe.")
		return
	}

	// 2. Obter o caminho absoluto do executável
	exePath, err := os.Executable()
	if err != nil {
		fmt.Println("Erro ao obter o caminho do executável:", err)
		return
	}

	exePath, err = filepath.Abs(exePath)
	if err != nil {
		fmt.Println("Erro ao obter o caminho absoluto do executável:", err)
		return
	}

	// Envolver o caminho do executável em aspas para lidar com espaços no caminho
	exePathQuoted := fmt.Sprintf("\"%s\"", exePath)

	// 3. Obter o nome de usuário atual
	currentUser, err := user.Current()
	if err != nil {
		fmt.Println("Erro ao obter o usuário atual:", err)
		return
	}

	username := currentUser.Username
	// No Windows, o formato pode ser DOMAIN\Username ou Username
	// Para garantir compatibilidade, podemos processar o nome de usuário
	if strings.Contains(username, "\\") {
		parts := strings.Split(username, "\\")
		username = parts[len(parts)-1]
	}

	// 4. Solicitar a senha do usuário
	fmt.Printf("Por favor, insira a senha para a conta administrador '%s': ", username)
	passwordBytes, err := readPassword()
	if err != nil {
		fmt.Println("\nErro ao ler a senha:", err)
		return
	}
	password := string(passwordBytes)

	cmd := exec.Command("schtasks",
		"/Create",
		"/SC", "ONSTART",
		"/RL", "HIGHEST",
		"/F",
		"/TN", taskName,
		"/TR", exePathQuoted,
		"/RU", username,
		"/RP", password,
	)

	// 6. Executar o comando
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Erro ao criar a tarefa agendada: %v\nSaída: %s\n", err, string(output))
		return
	}

	fmt.Printf("Tarefa agendada '%s' criada com sucesso.\n", taskName)
}

// isTaskExists verifica se uma tarefa agendada com o nome especificado já existe.
func isTaskExists(taskName string) bool {
	cmd := exec.Command("schtasks", "/Query", "/TN", taskName)
	err := cmd.Run()
	return err == nil
}

// readPassword lê a senha do usuário sem ecoar no terminal (apenas para sistemas compatíveis)
func readPassword() ([]byte, error) {
	return readPasswordFromStdin()
}

func readPasswordFromStdin() ([]byte, error) {
	return termReadPassword(int(os.Stdin.Fd()))
}

// termReadPassword lê a senha usando a biblioteca term
func termReadPassword(fd int) ([]byte, error) {
	fmt.Println()
	password, err := term.ReadPassword(fd)
	return password, err
}
