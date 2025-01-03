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

var (
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

	// Endpoints
	r.HandleFunc("/api/suspects", handleReceiveSuspect).Methods("POST")
	r.HandleFunc("/api/suspects/{id}/response", handleRespondSuspect).Methods("POST")
	r.HandleFunc("/api/suspects", handleListSuspects).Methods("GET")
	r.HandleFunc("/api/suspects/responses", handleGetResponses).Methods("GET")

	// Servir arquivos estáticos e a interface web
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))

	// Iniciar o consumidor da fila de [SUSPEITO]
	go handleSuspects()

	// Iniciar o consumidor da UI
	go handleUIUpdates()

	fmt.Println("Servidor HTTP iniciado na porta 8080")
	log.Fatal(http.ListenAndServe(":8080", r))
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

// Função para logar a mensagem em um suspeito com data e horário
func logMessage(msg SuspectRequest, response string) {
	// Obter o horário atual formatado
	currentTime := time.Now().Format("2006-01-02 15:04:05")

	// Formatar a entrada de log incluindo data e horário
	logEntry := fmt.Sprintf("ID=%d, Agent=%s, Message=%s, Response=%s, DateTime=%s\n",
		msg.ID, msg.Agent, msg.Message, response, currentTime)

	// Abrir/criar o arquivo de log em modo append e escrita
	f, err := os.OpenFile("log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Erro ao abrir log:", err)
		return
	}
	defer f.Close()

	// Escrever a entrada de log no arquivo
	if _, err = f.WriteString(logEntry); err != nil {
		log.Println("Erro ao escrever no log:", err)
	}
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
