package notifier

import (
	"fmt"
	"os"

	gomail "gopkg.in/gomail.v2"
)

func SendEmail(arquivo string) {
	// Verifica se o arquivo está vazio
	info, err := os.Stat(arquivo)
	if err != nil {
		fmt.Println("Erro ao verificar o arquivo:", err)
		return
	}

	if info.Size() == 0 {
		fmt.Println("Arquivo de log está vazio. Não será enviado por e-mail.")
		return
	}

	m := gomail.NewMessage()
	email := "teste@gmail.com" //usar Gmail e pesquisar criar senha de APP
	senha := "usarSuaSenhaDeAPPaqui"

	m.SetHeader("From", email)
	m.SetHeader("To", email) // Pode adicionar mais destinatários, se quiser
	m.SetHeader("Subject", "Alerta do Agente EDR (Windows)")
	m.SetBody("text/plain", "Segue em anexo o arquivo de log com possíveis eventos suspeitos.")
	m.Attach(arquivo)

	d := gomail.NewDialer("smtp.gmail.com", 587, email, senha)

	if err := d.DialAndSend(m); err != nil {
		fmt.Println("Erro ao enviar o e-mail:", err)
	} else {
		fmt.Println("E-mail enviado com sucesso!")
	}
}
