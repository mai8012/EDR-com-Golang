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
	suspiciousProcessNames = []string{ // Nome de processos suspeitos
		"powershell", "cmd.exe", "wscript", "cscript", "mshta",
		"rundll32", "regsvr32", "bitsadmin", "certutil", "wmic",
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
