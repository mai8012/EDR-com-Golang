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
	agents               = make(map[string]time.Time)
	agentsLock           sync.Mutex
	suspectChan          = make(chan SuspectRequest, 1000)
	uiChan               = make(chan func(), 1000)
	messages             = []SuspectRequest{}
	messagesLock         sync.Mutex
	pendingResponses     = make(map[int]string)
	pendingResponsesLock sync.Mutex
	suspectID            int
	suspectIDLock        sync.Mutex
)

func main() {
	r := mux.NewRouter()

	// Endpoints Suspeitos
	r.HandleFunc("/api/suspects", handleReceiveSuspect).Methods("POST")
	r.HandleFunc("/api/suspects/{id}/response", handleRespondSuspect).Methods("POST")
	r.HandleFunc("/api/suspects", handleListSuspects).Methods("GET")
	r.HandleFunc("/api/suspects/responses", handleGetResponses).Methods("GET")

	// Novos endpoints para monitoramento de agentes online
	r.HandleFunc("/api/ping", handlePing).Methods("POST")
	r.HandleFunc("/api/online_count", handleOnlineCount).Methods("GET")
	r.HandleFunc("/api/online_agents", handleOnlineAgents).Methods("GET")

	// Endpoint log.JSON
	r.HandleFunc("/api/log", handleGetLog).Methods("GET")

	// Servir arquivos estáticos e a interface web
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))

	// Iniciar o consumidor da fila de [SUSPEITO]
	go handleSuspects()

	// Iniciar o consumidor da UI
	go handleUIUpdates()

	go cleanupAgents() // Iniciar a rotina de limpeza de agentes

	fmt.Println("Servidor HTTP iniciado na porta 7777")
	log.Fatal(http.ListenAndServe(":7777", r))
}

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////  PING  ///////////////////////////////////////////////////////////
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////Ping Fim///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////Leitura Suspeitos//////////////////////////////////////////////////
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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

	// Achar no slice
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

	// Resposta HTTP
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
				// Remover a resposta após ser enviada
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
		// Processar a suspeita e aguardar a resposta do operador
		fmt.Printf("Nova suspeita recebida: %+v\n", suspect)
	}
}

// handleUIUpdates executa funções enviadas para o canal de UI na main goroutine.
func handleUIUpdates() {
	for updateFunc := range uiChan {
		updateFunc()
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////Leitura Suspeitos Fim//////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////Log JSON///////////////////////////////////////////////////////////
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
type LogEntry struct {
	ID       int    `json:"id"`
	Agent    string `json:"agent"`
	Message  string `json:"message"`
	Response string `json:"response"`
	DateTime string `json:"date_time"`
}

// Função para logar no formato JSON
func logMessage(msg SuspectRequest, response string) {
	// Montar o struct
	entry := LogEntry{
		ID:       msg.ID,
		Agent:    msg.Agent,
		Message:  msg.Message,
		Response: response,
		DateTime: time.Now().Format("2006-01-02 15:04:05"),
	}

	// Ler o arquivo inteiro (caso queira manter um array de logs)
	// Se o arquivo ainda não existir ou estiver vazio, iniciamos um array vazio.
	var logs []LogEntry

	// Se conseguir abrir, tentamos decodificar
	b, err := os.ReadFile("log.json")
	if err == nil {
		// Se não der erro, tentamos decodificar o que tem lá
		_ = json.Unmarshal(b, &logs)
	}

	// Adiciona o novo log
	logs = append(logs, entry)

	// (Re)escreve o arquivo JSON com o array completo
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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////Log JSON Fim///////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
