package monitor

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/windows"
)

type SuspiciousProcess struct {
	Name string
	Path string
	PID  int
	IPs  string
	Host string
}

// Variáveis e listas de suspeitos
var (
	ignoredExecutables = []string{}
	allowedProcesses   = make(map[string]bool)
	suspiciousCache    = sync.Map{}
	suspiciousDirs     = []string{ //Diretório monitorado
		`c:\`, // Use letras minúsculas por consistência
	}
	ignoredDirs = []string{ // Diretórios a serem ignorados
		`c:\windows\`,
		`c:\programdata\`,
		`c:\program files\`,
		`c:\program files (x86)\`,
	}
	// Lista de nomes de processos suspeitos em sistemas Windows.
	// Cada processo é comentado com uma breve descrição do motivo da suspeita.
	suspiciousProcessNames = []string{
		// Processos já existentes
		"powershell",         // Utilizado para scripts; frequentemente abusado para execução de código malicioso.
		"cmd.exe",            // Prompt de comando; pode ser usado para executar comandos maliciosos.
		"wscript",            // Host de scripts Windows; pode executar scripts maliciosos.
		"cscript",            // Host de scripts Windows em modo de console; similar ao wscript.
		"mshta",              // Utilitário para executar aplicações HTML; pode ser usado para hospedar código malicioso.
		"rundll32",           // Executa funções em DLLs; pode ser abusado para carregar e executar código malicioso.
		"regsvr32",           // Registra DLLs; frequentemente usado para executar scripts ou código malicioso.
		"bitsadmin",          // Gerencia transferências em segundo plano; pode ser usado para baixar payloads maliciosos.
		"certutil",           // Ferramenta para manipular certificados; pode ser usada para decodificar dados maliciosos.
		"wmic",               // Interface de linha de comando para WMI; pode executar comandos maliciosos no sistema.
		"installutil.exe",    // Ferramenta .NET para instalar serviços; pode ser usada para executar código arbitrário.
		"schtasks.exe",       // Permite agendar tarefas; pode ser usado para persistência ou execução futura de payloads.
		"taskhost.exe",       // Hospeda processos do Windows; pode ser explorado para mascarar atividades maliciosas.
		"taskeng.exe",        // Motor de agendamento de tarefas; potencial para abuso em agendamentos maliciosos.
		"powershell_ise.exe", // Ambiente interativo do PowerShell; permite a execução e depuração de scripts maliciosos.
		"msiexec.exe",        // Instalador do Windows para pacotes MSI; pode instalar software malicioso disfarçado.
		"reg.exe",            // Manipula o registro do Windows; pode alterar configurações de segurança ou persistência.
		"regedit.exe",        // Editor do registro; similar ao reg.exe, com capacidade para modificar configurações críticas.
		"vssadmin.exe",       // Gerencia snapshots de volume; pode excluir backups ou esconder atividades.
		"at.exe",             // Agendamento de tarefas; similar ao schtasks.exe, permitindo agendar execuções maliciosas.
		"net.exe",            // Executa comandos de rede; pode ser usado para movimentação lateral ou modificações de rede.
		"netsh.exe",          // Configurações de rede; pode alterar configurações de firewall ou rede para benefício malicioso.
		"ftp.exe",            // Cliente FTP do Windows; pode transferir dados para ou de servidores controlados pelo atacante.
		"conhost.exe",        // Processo legítimo, mas pode ser explorado para ocultar atividades maliciosas ou injetar código.
		"bitsadmin.exe",      // Gerencia transferências de arquivos em segundo plano; pode ser usado para baixar malware.
		"lp.exe",             // Processo de impressão; pode ser abusado para executar comandos no sistema.
		"rmi.exe",            // Pode referir-se a diversos processos; análise adicional necessária.
		"cscript.exe",        // Já incluído, mas reforça a capacidade de executar scripts via linha de comando.
		"wscript.exe",        // Já incluído, similar ao cscript.exe para execução de scripts.
	}
)

const (
	processScanInterval = 10 * time.Second
)

// Syscall definitions
var (
	ntdll            = windows.NewLazySystemDLL("ntdll.dll")
	ntSuspendProcess = ntdll.NewProc("NtSuspendProcess")
	ntResumeProcess  = ntdll.NewProc("NtResumeProcess")
)

func isIgnoredDirectory(path string) bool {
	lowerPath := strings.ToLower(path) // Normalizar para minúsculas
	for _, ignored := range ignoredDirs {
		if strings.HasPrefix(lowerPath, ignored) { // Comparar com diretórios ignorados em minúsculas
			return true
		}
	}
	return false
}

// WatchProcesses monitora processos e suspende suspeitos
func WatchProcesses(suspicionsChan chan<- SuspiciousProcess) {
	for {
		processes, err := process.Processes()
		if err != nil {
			log.Println("Erro ao obter lista de processos:", err)
			time.Sleep(processScanInterval)
			continue
		}

		hostname, _ := os.Hostname()
		ipString := gatherLocalIPs()
		activeKeys := make(map[string]bool)

		for _, p := range processes {
			exe, errExe := p.Exe()
			name, errName := p.Name()

			if errExe != nil || errName != nil || exe == "" || name == "" {
				continue
			}

			// Ignorar processos em diretórios ignorados
			if isIgnoredDirectory(exe) {
				continue
			}

			// Ignorar processos permitidos
			if isIgnored(exe) {
				continue
			}

			// Verificar se está em diretórios suspeitos
			isFromSuspiciousDir := false
			exeLower := strings.ToLower(exe) // Normalize o caminho do executável
			for _, dir := range suspiciousDirs {
				if strings.HasPrefix(exeLower, dir) { // Use HasPrefix para comparar diretórios
					isFromSuspiciousDir = true
					break
				}
			}

			// Verificar se o nome está na lista de suspeitos
			isSuspectProcess := false
			for _, suspect := range suspiciousProcessNames {
				if strings.Contains(strings.ToLower(name), suspect) {
					isSuspectProcess = true
					break
				}
			}

			if isFromSuspiciousDir || isSuspectProcess {
				key := makeKey(int(p.Pid), exe)
				activeKeys[key] = true

				if !alreadyLogged(key) {
					log.Printf("[SUSPEITO] Nome: %s | Caminho: %s | PID: %d | IP: %s | Hostname: %s",
						name, exe, p.Pid, ipString, hostname)

					// Suspende o processo
					err := suspendProcess(int(p.Pid))
					if err != nil {
						log.Printf("Erro ao suspender processo PID %d: %v", p.Pid, err)
					} else {
						log.Printf("Processo PID %d suspenso enquanto aguarda decisão.", p.Pid)
					}

					// Envia o processo para avaliação
					suspicionsChan <- SuspiciousProcess{
						Name: name,
						Path: exe,
						PID:  int(p.Pid),
						IPs:  ipString,
						Host: hostname,
					}

					// Marca como logado
					suspiciousCache.Store(key, time.Now())
				}
			}
		}

		// Limpar processos não ativos
		suspiciousCache.Range(func(k, v interface{}) bool {
			keyStr := k.(string)
			if !activeKeys[keyStr] {
				suspiciousCache.Delete(keyStr)
			}
			return true
		})

		time.Sleep(processScanInterval)
	}
}

// Constantes para permissões de processo
const PROCESS_SUSPEND_RESUME uint32 = 0x0800

// Suspende um processo pelo PID (Windows)
func suspendProcess(pid int) error {
	handle, err := windows.OpenProcess(PROCESS_SUSPEND_RESUME, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("não foi possível abrir o processo PID %d: %v", pid, err)
	}
	defer windows.CloseHandle(handle)

	r, _, _ := ntSuspendProcess.Call(uintptr(handle))
	if r != 0 {
		return fmt.Errorf("erro ao suspender o processo PID %d", pid)
	}
	return nil
}

// Retoma um processo pelo PID (Windows)
func ResumeProcess(pid int) error {
	handle, err := windows.OpenProcess(PROCESS_SUSPEND_RESUME, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("não foi possível abrir o processo PID %d: %v", pid, err)
	}
	defer windows.CloseHandle(handle)

	r, _, _ := ntResumeProcess.Call(uintptr(handle))
	if r != 0 {
		return fmt.Errorf("erro ao retomar o processo PID %d", pid)
	}
	return nil
}

func isIgnored(exePath string) bool {
	lowerExePath := strings.ToLower(exePath)
	for _, ign := range ignoredExecutables {
		if lowerExePath == strings.ToLower(ign) {
			return true
		}
	}
	return allowedProcesses[lowerExePath]
}

func gatherLocalIPs() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "Não encontrado"
	}
	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPNet:
			ip := v.IP
			if ip != nil && !ip.IsLoopback() && ip.To4() != nil {
				if strings.HasPrefix(ip.String(), "192.168.") { //Adicione sua faixa de IP
					return ip.String()
				}
			}
		}
	}
	return "Não encontrado"
}

func makeKey(pid int, exePath string) string {
	return fmt.Sprintf("%d|%s", pid, strings.ToLower(strings.TrimSpace(exePath)))
}

func alreadyLogged(key string) bool {
	_, found := suspiciousCache.Load(key)
	return found
}
