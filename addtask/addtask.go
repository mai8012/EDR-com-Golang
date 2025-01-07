package addtask

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/term" //Manipulação avançada de terminais, útil para interações seguras com o usuário.
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

	// 6. Executar o comando
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
