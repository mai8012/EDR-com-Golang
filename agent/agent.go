package main

import (
	"bufio"
	"edr-agent/monitor"
	"edr-agent/notifier"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	psutil "github.com/shirou/gopsutil/process"
)

const (
	logFilePath    = "log.txt"
	serverAddress  = "192.168.2.106:8080" // Altere para o endereço do seu servidor
	processScanInt = 10 * time.Second
)

var (
	// Mapa para mapear IDs de mensagens para processos suspeitos
	messageIDToProcess     = make(map[int]monitor.SuspiciousProcess)
	messageIDToProcessLock sync.Mutex

	// Fila para rastrear mensagens pendentes para deduplicação
	pendingResponses     = make([]int, 0)
	pendingResponsesLock sync.Mutex

	// Contador para IDs únicos
	suspectID     = 0
	suspectIDLock sync.Mutex
)

// SuspiciousProcess representa um processo suspeito detectado.
type SuspiciousProcess struct {
	Name string
	Path string
	PID  int
	IPs  string
	Host string
}

// Decision representa a resposta do servidor para uma suspeita.
type Decision struct {
	MessageID int
	Response  string // "y" ou "n"
}

// suspectWriter grava no log local e também envia mensagens ao servidor (se conectado).
type suspectWriter struct {
	file *os.File
	conn net.Conn
	mu   sync.Mutex
}

// Write grava no log local e envia ao servidor se a conexão estiver estabelecida.
func (w *suspectWriter) Write(p []byte) (n int, err error) {
	line := string(p)
	if strings.Contains(line, "[SUSPEITO]") ||
		strings.Contains(line, "[FINALIZADO]") ||
		strings.Contains(line, "[LIBERADO]") {
		if _, err := w.file.Write([]byte(line)); err != nil {
			fmt.Println("Erro ao escrever em arquivo de log:", err)
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.conn != nil {
			if _, err := w.conn.Write([]byte(line)); err != nil {
				fmt.Println("Erro ao enviar dados ao servidor:", err)
			}
		}
	}
	return len(p), nil
}

func main() {
	// Abrir arquivo de log
	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("Erro ao criar/abrir arquivo de log:", err)
		return
	}
	defer logFile.Close()

	// Configurar log
	sw := &suspectWriter{file: logFile}
	mw := io.MultiWriter(os.Stdout, sw)
	log.SetOutput(mw)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	log.Println("Iniciando agente EDR (Windows)...")

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

	// Goroutine para enviar email de log
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-time.After(120 * time.Minute):
				notifier.SendEmail(logFilePath)
			case <-stopChan:
				notifier.SendEmail(logFilePath)
				return
			}
		}
	}()

	// Canal para detectar perda de conexão
	connectionLost := make(chan struct{})

	// Goroutine para gerenciar conexão e enviar/receber
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			// Estabelecer conexão com o servidor
			conn, err := connectToServer(serverAddress)
			if err != nil {
				log.Fatalf("Falha ao conectar ao servidor: %v", err)
			}

			log.Println("Conectado ao servidor.")

			// Iniciar goroutines para enviar suspeitas e receber decisões
			var sendWg sync.WaitGroup
			sendWg.Add(1)
			go func() {
				defer sendWg.Done()
				sendSuspicions(conn, suspicionsChan)
			}()
			sendWg.Add(1)
			go func() {
				defer sendWg.Done()
				receiveDecisions(conn, decisionsChan, connectionLost)
			}()

			// Aguarda sinal de perda de conexão
			<-connectionLost

			log.Println("Conexão perdida com o servidor.")

			// Enviar "n" para mensagens pendentes
			sendNForPendingMessages(decisionsChan)

			// Fecha a conexão explicitamente
			if err := conn.Close(); err != nil {
				log.Printf("Erro ao fechar a conexão: %v", err)
			}

			log.Println("Tentando reconectar em 5 segundos...")
			time.Sleep(5 * time.Second)
		}
	}()

	// Aguarda sinal de interrupção
	<-stopChan
	log.Println("Encerrando agente EDR...")

	// Fechar os canais
	close(suspicionsChan)
	close(decisionsChan)

	wg.Wait()
}

// connectToServer tenta estabelecer uma conexão TCP com o servidor.
func connectToServer(address string) (net.Conn, error) {
	for {
		conn, err := net.Dial("tcp", address)
		if err == nil {
			fmt.Println("Conectado ao servidor TCP em", address)
			return conn, nil
		}
		fmt.Println("Erro ao conectar ao servidor:", err)
		fmt.Println("Tentando novamente em 5 segundos...")
		time.Sleep(5 * time.Second)
	}
}

// sendSuspicions envia mensagens de processos suspeitos ao servidor.
func sendSuspicions(conn net.Conn, suspicionsChan <-chan monitor.SuspiciousProcess) {
	for suspect := range suspicionsChan {
		// Gera um ID único para a mensagem
		messageID := getNextMessageID()

		// Cria a mensagem no formato esperado pelo servidor
		message := fmt.Sprintf("[SUSPEITO] ID:%d|Name:%s|Path:%s|PID:%d|IP:%s|Host:%s",
			messageID, suspect.Name, suspect.Path, suspect.PID, suspect.IPs, suspect.Host)

		// Envia a mensagem ao servidor com tentativa de reenvio em caso de falha
		for {
			_, err := fmt.Fprintln(conn, message)
			if err != nil {
				log.Printf("[ERRO] Falha ao enviar suspeito ao servidor: %v", err)
				log.Println("Tentando enviar novamente...")
				time.Sleep(5 * time.Minute)
				continue
			}
			break
		}

		log.Printf("Mensagem enviada ao servidor: %s", message)

		// Mapeia o ID para o processo suspeito
		messageIDToProcessLock.Lock()
		messageIDToProcess[messageID] = monitor.SuspiciousProcess{
			Name: suspect.Name,
			Path: suspect.Path,
			PID:  suspect.PID,
			IPs:  suspect.IPs,
			Host: suspect.Host,
		}
		messageIDToProcessLock.Unlock()

		// Adiciona o messageID à fila de pendentes
		pendingResponsesLock.Lock()
		pendingResponses = append(pendingResponses, messageID)
		pendingResponsesLock.Unlock()
	}
}

// receiveDecisions lê mensagens do servidor e envia para decisionsChan.
func receiveDecisions(conn net.Conn, decisionsChan chan<- Decision, connectionLost chan<- struct{}) {
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		lowerMsg := strings.ToLower(strings.TrimSpace(line))

		if lowerMsg == "y" || lowerMsg == "n" {
			var decision Decision

			pendingResponsesLock.Lock()
			if len(pendingResponses) == 0 {
				log.Printf("[AVISO] Recebeu resposta '%s' sem mensagens pendentes.", lowerMsg)
				pendingResponsesLock.Unlock()
				continue
			}
			// Obtém o primeiro messageID da fila
			decision.MessageID = pendingResponses[0]
			// Remove o primeiro elemento da fila
			pendingResponses = pendingResponses[1:]
			pendingResponsesLock.Unlock()

			decision.Response = lowerMsg
			decisionsChan <- decision
		} else {
			log.Printf("[AVISO] Formato de resposta desconhecido: %s", line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[ERRO] Erro ao ler do servidor: %v", err)
		// Enviar sinal de perda de conexão
		connectionLost <- struct{}{}
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

		// Não há necessidade de deduplicar, pois a fila já garante a ordem

		if decision.Response == "y" {
			// Resposta 'y': Retoma o processo
			err := monitor.ResumeProcess(suspect.PID) // Retoma o processo
			if err != nil {
				log.Printf("[ERRO] ao retomar processo PID %d: %v", suspect.PID, err)
			} else {
				log.Printf("[LIBERADO] Processo %s (PID=%d) retomado com sucesso.\n", suspect.Path, suspect.PID)
			}
		} else {
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

// sendNForPendingMessages envia "n" para todas as mensagens pendentes.
func sendNForPendingMessages(decisionsChan chan<- Decision) {
	pendingResponsesLock.Lock()
	defer pendingResponsesLock.Unlock()

	for _, messageID := range pendingResponses {
		decision := Decision{
			MessageID: messageID,
			Response:  "n",
		}
		decisionsChan <- decision
		log.Printf("[AUTO-RESPOSTA] Enviando 'n' para ID %d devido à perda de conexão.", messageID)
	}

	// Limpar a fila de pendentes
	pendingResponses = pendingResponses[:0]
}
