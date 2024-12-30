EDR Agent é uma aplicação desenvolvida em Go (Golang) para monitoramento e resposta a atividades suspeitas em endpoints Windows. O agente realiza as seguintes funcionalidades principais:

Monitoramento de Processos:

Escaneamento Contínuo: O agente escaneia os processos em execução no sistema a cada 10 segundos.
Critérios de Suspeita:
Diretórios Monitorados: Detecta processos executados a partir de diretórios específicos considerados suspeitos (por exemplo, C:\).
Nomes de Processos Suspeitos: Identifica processos com nomes que indicam potencial atividade maliciosa, como powershell, cmd.exe, wscript, entre outros.
Ignorar Processos Legítimos: Processos localizados em diretórios ignorados (como C:\Windows\, C:\Program Files\, etc.) ou que estão na lista de processos permitidos são excluídos da análise.
Gestão de Processos Suspeitos:

Suspensão de Processos: Quando um processo suspeito é identificado, o agente suspende sua execução temporariamente utilizando chamadas de sistema específicas do Windows (NtSuspendProcess).
Registro de Suspeitas: Detalhes do processo suspeito, incluindo nome, caminho, PID, endereços IP e hostname, são registrados localmente em um arquivo de log (log.txt) e enviados para um servidor central para avaliação.
Comunicação com o Servidor:

Conexão TCP: Estabelece e mantém uma conexão TCP com o servidor especificado (192.168.2.106:8080).
Envio de Dados: Envia informações detalhadas sobre processos suspeitos para o servidor.
Recepção de Decisões: Recebe decisões do servidor para cada processo suspeito:
"y" (Yes): Permite e retoma a execução do processo.
"n" (No): Finaliza o processo de forma definitiva.
Gestão de Respostas e Ações:

Mapeamento de Mensagens: Mantém um mapeamento de IDs de mensagens para processos suspeitos, garantindo que cada decisão recebida corresponda ao processo correto.
Tratamento de Respostas Automáticas: Em caso de perda de conexão com o servidor, o agente envia automaticamente a resposta "n" para todos os processos pendentes, finalizando-os.
Envio de Logs por Email:

Envio Periódico: A cada 120 minutos, o agente envia o arquivo de log por email utilizando o módulo notifier.
Envio em Interrupção: Garante o envio final do log ao receber sinais de interrupção do sistema.
Resiliência e Reconexão:

Detecção de Perda de Conexão: Monitora a conexão com o servidor e detecta qualquer perda de conexão.
Reconexão Automática: Tenta reconectar automaticamente ao servidor a cada 5 segundos em caso de falha na conexão.
Gestão de Mensagens Pendentes: Assegura que todas as mensagens pendentes sejam tratadas adequadamente em caso de desconexão.
Estrutura do Código
Pacotes Importados:

Utiliza pacotes padrão do Go como net, os, log, entre outros.
Depende de pacotes externos como gopsutil para interação com processos do sistema e golang.org/x/sys/windows para chamadas de sistema específicas do Windows.
Componentes Principais:

SuspiciousProcess: Estrutura que representa um processo suspeito detectado.
Decision: Estrutura que representa a resposta do servidor para uma suspeita específica.
suspectWriter: Implementa a interface io.Writer para registrar logs localmente e enviar dados ao servidor.
monitor: Pacote responsável pelo monitoramento de processos, detecção de suspeitas, suspensão e retomada de processos.
notifier: Pacote responsável pelo envio de notificações por email.
Goroutines:

Monitoramento de Processos: Monitora continuamente os processos em execução.
Processamento de Decisões: Trata as respostas recebidas do servidor.
Envio de Logs por Email: Gerencia o envio periódico de logs.
Gerenciamento de Conexão: Mantém a conexão com o servidor e lida com reconexões.
