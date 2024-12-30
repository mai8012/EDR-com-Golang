package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// Endereço em que o servidor irá escutar.
const serverAddress = "0.0.0.0:8080" //Define a porta a sua escolha

// suspectRequest representa uma mensagem [SUSPEITO] recebida,
// incluindo a conexão de onde veio e um ID único.
type suspectRequest struct {
	id      int
	conn    net.Conn
	message string
}

// Canal (fila) para armazenar todas as mensagens [SUSPEITO].
var suspectChan = make(chan suspectRequest, 1000)

// Canal para enviar funções de atualização da UI para a goroutine principal.
var uiChan = make(chan func(), 1000)

// Variáveis globais para interface e sincronização.
var (
	messages       *widget.Label // Área onde exibimos os logs
	input          *widget.Entry // Campo de texto para resposta
	currentMessage *widget.Label // Label para mostrar a mensagem atual
	sendButton     *widget.Button
	inputLock      sync.Mutex // Lock para manipular input/botão

	// Variáveis para atribuir IDs únicos às mensagens suspeitas.
	suspectID     int
	suspectIDLock sync.Mutex

	// Mapa para rastrear mensagens [SUSPEITO] pendentes e evitar duplicatas.
	pendingMessages     map[string]bool = make(map[string]bool)
	pendingMessagesLock sync.Mutex
)

func main() {
	// Cria a aplicação Fyne
	a := app.New()
	w := a.NewWindow("Servidor TCP")
	w.Resize(fyne.NewSize(600, 400))

	// Label para exibir as mensagens no servidor
	messages = widget.NewLabel("")
	scroll := container.NewVScroll(messages)
	scroll.SetMinSize(fyne.NewSize(600, 250)) // Ajustado para dar espaço para currentMessage

	// Label para exibir a mensagem atual sendo respondida
	currentMessage = widget.NewLabel("Nenhuma mensagem para responder no momento.")
	currentMessage.Wrapping = fyne.TextWrapWord

	// Campo de entrada para a resposta (y/n)
	input = widget.NewEntry()
	input.SetPlaceHolder("Digite sua resposta (y/n)...")

	// Botão "Enviar"
	sendButton = widget.NewButton("Enviar", func() {})
	sendButton.Disable() // Começa desabilitado

	// Layout da interface
	w.SetContent(container.NewBorder(
		nil, // topo
		container.NewVBox(
			currentMessage, // Label para mensagem atual
			container.NewVBox(
				input,      // Campo de entrada
				sendButton, // Botão Enviar ao lado
			),
		), // Layout na parte inferior
		nil, nil, // Sem conteúdo nas laterais
		scroll, // Conteúdo central (área de rolagem)
	))

	// Inicia o servidor em background
	go startServer()

	// Inicia o consumidor da fila de [SUSPEITO]
	go handleSuspects()

	// Inicia a goroutine de atualização da UI
	go handleUIUpdates()

	// Exibe a janela e executa
	w.ShowAndRun()
}

// startServer inicia o servidor TCP e aguarda conexões.
func startServer() {
	ln, err := net.Listen("tcp", serverAddress)
	if err != nil {
		enqueueUIUpdate(func() {
			appendMessage(fmt.Sprintf("Erro ao iniciar listener: %v\n", err))
		})
		return
	}
	defer ln.Close()

	enqueueUIUpdate(func() {
		appendMessage(fmt.Sprintf("Servidor escutando em %s...\n", serverAddress))
	})

	for {
		conn, err := ln.Accept()
		if err != nil {
			enqueueUIUpdate(func() {
				appendMessage(fmt.Sprintf("Erro ao aceitar conexão: %v\n", err))
			})
			continue
		}
		enqueueUIUpdate(func() {
			appendMessage(fmt.Sprintf("Nova conexão de: %s\n", conn.RemoteAddr()))
		})

		// Trata cada conexão em uma goroutine separada
		go handleConnection(conn)
	}
}

// handleConnection recebe as mensagens de um agente.
func handleConnection(conn net.Conn) {
	defer func() {
		enqueueUIUpdate(func() {
			appendMessage(fmt.Sprintf("Conexão encerrada com: %s\n", conn.RemoteAddr()))
		})
		conn.Close()
	}()

	agentScanner := bufio.NewScanner(conn)
	for agentScanner.Scan() {
		line := agentScanner.Text()
		enqueueUIUpdate(func() {
			appendMessage(fmt.Sprintf("[AGENTE %s] Recebido: %s\n", conn.RemoteAddr(), line))
		})

		// Se for [SUSPEITO], colocamos na fila (suspectChan) com deduplicação
		if strings.Contains(line, "[SUSPEITO]") {
			enqueueUIUpdate(func() {
				appendMessage("[SERVIDOR] Chegou um [SUSPEITO], adicionando à fila...\n")
			})

			// Cria a chave para deduplicação: "remoteAddr:message"
			key := fmt.Sprintf("%s:%s", conn.RemoteAddr().String(), line)

			// Verifica se a mensagem já está pendente
			pendingMessagesLock.Lock()
			if _, exists := pendingMessages[key]; exists {
				// Mensagem duplicada, ignora enfileiramento
				appendMessage(fmt.Sprintf("[SERVIDOR] Mensagem duplicada ignorada: %s\n", line))
				pendingMessagesLock.Unlock()
				continue
			}

			// Marca a mensagem como pendente
			pendingMessages[key] = true
			pendingMessagesLock.Unlock()

			// Atribui um ID único à mensagem
			suspectIDLock.Lock()
			suspectID++
			currentID := suspectID
			suspectIDLock.Unlock()

			// Envia para o canal
			suspectChan <- suspectRequest{
				id:      currentID,
				conn:    conn,
				message: line,
			}

		} else {
			// Mensagem sem necessidade de resposta
			enqueueUIUpdate(func() {
				appendMessage(fmt.Sprintf("[SERVIDOR] Mensagem normal: %s\n", line))
			})
		}
	}

	if err := agentScanner.Err(); err != nil {
		log.Println("Erro ao ler do agente:", err)
	}
}

// handleSuspects processa cada [SUSPEITO] da fila, aguardando resposta do operador.
func handleSuspects() {
	for suspect := range suspectChan {
		// Temos um novo [SUSPEITO] para responder
		currentMsg := fmt.Sprintf("[SUSPEITO #%d] de %s: %s", suspect.id, suspect.conn.RemoteAddr(), suspect.message)

		// Envia atualização para a UI definir a mensagem atual
		enqueueUIUpdate(func() {
			appendCurrentMessage(currentMsg)
			sendButton.Enable()
		})

		// Cria um canal para sinalizar que a resposta foi enviada
		done := make(chan struct{})

		// Define a ação do botão "Enviar"
		inputLock.Lock()
		sendButton.OnTapped = func() {
			response := strings.TrimSpace(strings.ToLower(input.Text))
			if response == "y" || response == "n" {
				// Envia a resposta ao agente
				_, err := suspect.conn.Write([]byte(response + "\n"))
				if err != nil {
					enqueueUIUpdate(func() {
						appendMessage(fmt.Sprintf("Erro ao enviar mensagem ao agente: %v\n", err))
					})
					return
				}
				enqueueUIUpdate(func() {
					appendMessage(fmt.Sprintf("[SERVIDOR] Resposta '%s' enviada para [SUSPEITO #%d] de %s\n", response, suspect.id, suspect.conn.RemoteAddr()))
					appendCurrentMessage("Nenhuma mensagem para responder no momento.")
					input.SetText("")
					sendButton.Disable()
				})

				// Remove a mensagem do mapa de pendentes
				key := fmt.Sprintf("%s:%s", suspect.conn.RemoteAddr().String(), suspect.message)
				pendingMessagesLock.Lock()
				delete(pendingMessages, key)
				pendingMessagesLock.Unlock()

				// Sinaliza que terminamos de responder
				close(done)
			} else {
				enqueueUIUpdate(func() {
					appendMessage("Comando inválido, por favor responda y/n\n")
				})
			}
		}
		inputLock.Unlock()

		// Aguarda a resposta ser enviada (bloqueia até o operador clicar corretamente)
		<-done
	}
}

// handleUIUpdates executa funções enviadas para o canal de UI na main goroutine.
func handleUIUpdates() {
	for updateFunc := range uiChan {
		updateFunc()
	}
}

// enqueueUIUpdate adiciona uma função ao canal de UI para ser executada na main goroutine.
func enqueueUIUpdate(f func()) {
	uiChan <- f
}

// appendMessage escreve novas linhas no label de mensagens.
func appendMessage(text string) {
	messages.SetText(messages.Text + text)
}

// appendCurrentMessage atualiza o label da mensagem atual
func appendCurrentMessage(text string) {
	currentMessage.SetText(text)
}
