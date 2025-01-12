package addtask

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

func AddScheduledTask() {
	taskName := "SystemEDR" // Nome da tarefa agendada

	// 1. Verificar se a tarefa já existe
	if IsTaskExists(taskName) {
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

	exePathQuoted := fmt.Sprintf("\"%s\"", exePath)

	currentUser, err := user.Current()
	if err != nil {
		fmt.Println("Erro ao obter o usuário atual:", err)
		return
	}

	username := currentUser.Username
	// DOMAIN\Username ou Username
	if strings.Contains(username, "\\") {
		parts := strings.Split(username, "\\")
		username = parts[len(parts)-1]
	}

	fmt.Printf("Por favor, insira a senha para a conta administrador '%s': ", username)
	passwordBytes, err := ReadPassword()
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

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Erro ao criar a tarefa agendada: %v\nSaída: %s\n", err, string(output))
		return
	}

	fmt.Printf("Tarefa agendada '%s' criada com sucesso.\n", taskName)
}

// isTaskExists verifica se uma tarefa agendada com o nome especificado já existe.
func IsTaskExists(taskName string) bool {
	cmd := exec.Command("schtasks", "/Query", "/TN", taskName)
	err := cmd.Run()
	return err == nil
}

// readPassword lê a senha do usuário sem ecoar no terminal (apenas para sistemas compatíveis)
func ReadPassword() ([]byte, error) {
	return ReadPasswordFromStdin()
}

func ReadPasswordFromStdin() ([]byte, error) {
	return TermReadPassword(int(os.Stdin.Fd()))
}

// termReadPassword lê a senha usando a biblioteca term
func TermReadPassword(fd int) ([]byte, error) {
	fmt.Println()
	password, err := term.ReadPassword(fd)
	return password, err
}
