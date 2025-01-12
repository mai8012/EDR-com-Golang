package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

type SuspectRequest struct {
	ID      int    `json:"id"`
	Message string `json:"message"`
	Agent   string `json:"agent"`
}

type Decision struct {
	MessageID int    `json:"message_id"`
	Response  string `json:"response"`
}

type Agent struct {
	ID       string
	LastPing time.Time
}

var (
	agents                  = make(map[string]time.Time)
	agentsLock              sync.Mutex
	suspectChan             = make(chan SuspectRequest, 1000)
	uiChan                  = make(chan func(), 1000)
	messages                = []SuspectRequest{}
	messagesLock            sync.Mutex
	pendingResponses        = make(map[int]string)
	pendingResponsesLock    sync.Mutex
	suspectID               int
	suspectIDLock           sync.Mutex
	serverStartTime         = time.Now()
	suspectProcessCount     int
	suspectProcessCountLock sync.Mutex
)

func main() {
	r := mux.NewRouter()

	// Endpoints Suspeitos
	r.HandleFunc("/api/suspects", handleReceiveSuspect).Methods("POST")
	r.HandleFunc("/api/suspects/{id}/response", handleRespondSuspect).Methods("POST")
	r.HandleFunc("/api/suspects", handleListSuspects).Methods("GET")
	r.HandleFunc("/api/suspects/responses", handleGetResponses).Methods("GET")

	// Novos endpoints para monitoramento de uptime e contador de processos suspeitos
	r.HandleFunc("/api/uptime", handleUptime).Methods("GET")
	r.HandleFunc("/api/suspect_count", handleSuspectCount).Methods("GET")

	// Novos endpoints para monitoramento de agentes online
	r.HandleFunc("/api/ping", handlePing).Methods("POST")
	r.HandleFunc("/api/online_count", handleOnlineCount).Methods("GET")
	r.HandleFunc("/api/online_agents", handleOnlineAgents).Methods("GET")

	// Endpoint log.JSON
	r.HandleFunc("/api/log", handleGetLog).Methods("GET")

	// Endpoint de logout
	r.HandleFunc("/api/logout", handleLogout).Methods("POST")

	// Protege o acesso aos arquivos estáticos com autenticação básica
	r.PathPrefix("/").Handler(basicAuth(http.FileServer(http.Dir("./static/"))))

	// Iniciar o consumidor da fila de [SUSPEITO]
	go handleSuspects()

	// Iniciar o consumidor da UI
	go handleUIUpdates()

	go cleanupAgents() // Iniciar a rotina de limpeza de agentes

	fmt.Println("Servidor HTTP iniciado na porta 7777")
	log.Fatal(http.ListenAndServe(":7777", r))
}

func basicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != "admin" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func handleOnlineAgents(w http.ResponseWriter, r *http.Request) {
	agentsLock.Lock()
	defer agentsLock.Unlock()

	// Extrair apenas as chaves do map
	var agentIDs []string
	for agentID := range agents {
		agentIDs = append(agentIDs, agentID)
	}

	// Retornar em JSON
	json.NewEncoder(w).Encode(agentIDs)
}

func cleanupAgents() {
	for {
		time.Sleep(10 * time.Second) // Intervalo de verificação

		cutoff := time.Now().Add(-180 * time.Second)
		agentsLock.Lock()
		for id, lastPing := range agents {
			if lastPing.Before(cutoff) {
				delete(agents, id)
			}
		}
		agentsLock.Unlock()
	}
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	agentsLock.Lock()
	agents[req.ID] = time.Now()
	agentsLock.Unlock()

	w.WriteHeader(http.StatusOK)
}

func handleOnlineCount(w http.ResponseWriter, r *http.Request) {
	agentsLock.Lock()
	count := len(agents)
	agentsLock.Unlock()

	json.NewEncoder(w).Encode(map[string]int{"online": count})
}

// handleReceiveSuspect recebe suspeitas dos agentes via POST
func handleReceiveSuspect(w http.ResponseWriter, r *http.Request) {
	var req SuspectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Atribuir um ID único
	suspectIDLock.Lock()
	suspectID++
	req.ID = suspectID
	suspectIDLock.Unlock()

	messagesLock.Lock()
	messages = append(messages, req)
	messagesLock.Unlock()

	// Incrementar o contador de processos suspeitos
	suspectProcessCountLock.Lock()
	suspectProcessCount++
	suspectProcessCountLock.Unlock()

	// Enviar para a fila de processamento
	suspectChan <- req

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]int{"id": req.ID})
}

// handleListSuspects lista todas as suspeitas
func handleListSuspects(w http.ResponseWriter, r *http.Request) {
	messagesLock.Lock()
	defer messagesLock.Unlock()
	json.NewEncoder(w).Encode(messages)
}

// handleRespondSuspect permite que o operador responda a uma suspeita
func handleRespondSuspect(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var reqBody struct {
		Response string `json:"response"` // "y" ou "n"
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var idInt int
	if _, err := fmt.Sscanf(id, "%d", &idInt); err != nil {
		http.Error(w, "ID inválido", http.StatusBadRequest)
		return
	}

	messagesLock.Lock()
	defer messagesLock.Unlock()

	var indexToRemove = -1
	var foundMessage SuspectRequest
	for i, m := range messages {
		if m.ID == idInt {
			indexToRemove = i
			foundMessage = m
			break
		}
	}

	if indexToRemove == -1 {
		http.Error(w, "Mensagem não encontrada", http.StatusNotFound)
		return
	}

	go logMessage(foundMessage, reqBody.Response)

	pendingResponsesLock.Lock()
	pendingResponses[foundMessage.ID] = reqBody.Response
	pendingResponsesLock.Unlock()

	messages = append(messages[:indexToRemove], messages[indexToRemove+1:]...)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "mensagem removida com sucesso"})
}

// handleGetResponses retorna as respostas para os IDs especificados
func handleGetResponses(w http.ResponseWriter, r *http.Request) {
	idsParam := r.URL.Query().Get("ids")
	if idsParam == "" {
		http.Error(w, "IDs são necessários", http.StatusBadRequest)
		return
	}

	var decisions []Decision
	var id int
	for _, part := range split(idsParam, ",") {
		if _, err := fmt.Sscanf(part, "%d", &id); err == nil {
			pendingResponsesLock.Lock()
			response, exists := pendingResponses[id]
			if exists {
				decisions = append(decisions, Decision{MessageID: id, Response: response})
				delete(pendingResponses, id)
			}
			pendingResponsesLock.Unlock()
		}
	}

	json.NewEncoder(w).Encode(decisions)
}

// split divide uma string com base no separador
func split(s, sep string) []string {
	var result []string
	current := ""
	for _, c := range s {
		if string(c) == sep {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// handleSuspects processa suspeitas da fila
func handleSuspects() {
	for suspect := range suspectChan {
		fmt.Printf("Nova suspeita recebida: %+v\n", suspect)
	}
}

// handleUIUpdates executa funções enviadas para o canal de UI na main goroutine.
func handleUIUpdates() {
	for updateFunc := range uiChan {
		updateFunc()
	}
}

type LogEntry struct {
	ID       int    `json:"id"`
	Agent    string `json:"agent"`
	Message  string `json:"message"`
	Response string `json:"response"`
	DateTime string `json:"date_time"`
}

// Função para logar no formato JSON
func logMessage(msg SuspectRequest, response string) {
	entry := LogEntry{
		ID:       msg.ID,
		Agent:    msg.Agent,
		Message:  msg.Message,
		Response: response,
		DateTime: time.Now().Format("2006-01-02 15:04:05"),
	}

	var logs []LogEntry

	b, err := os.ReadFile("log.json")
	if err == nil {

		_ = json.Unmarshal(b, &logs)
	}

	logs = append(logs, entry)

	newData, err := json.MarshalIndent(logs, "", "  ")
	if err != nil {
		log.Println("Erro ao converter logs para JSON:", err)
		return
	}

	err = os.WriteFile("log.json", newData, 0644)
	if err != nil {
		log.Println("Erro ao gravar log.json:", err)
	}
}

func handleGetLog(w http.ResponseWriter, r *http.Request) {
	content, err := os.ReadFile("log.json")
	if err != nil {
		http.Error(w, "Não foi possível ler o log.json", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(content)
}

// handleUptime retorna o uptime do servidor
func handleUptime(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(serverStartTime)
	json.NewEncoder(w).Encode(map[string]string{"uptime": uptime.String()})
}

// handleSuspectCount retorna o contador de processos suspeitos
func handleSuspectCount(w http.ResponseWriter, r *http.Request) {
	suspectProcessCountLock.Lock()
	count := suspectProcessCount
	suspectProcessCountLock.Unlock()
	json.NewEncoder(w).Encode(map[string]int{"suspect_count": count})
}
