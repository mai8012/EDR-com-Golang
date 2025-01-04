EDR Agent é uma aplicação desenvolvida em Go (Golang) para monitoramento e resposta a atividades suspeitas em endpoints Windows. O agente realiza as seguintes funcionalidades principais:

Monitoramento de Processos:

Escaneamento Contínuo: O agente escaneia os processos em execução no sistema.
Critérios de Suspeita:
Diretórios Monitorados: Detecta processos executados a partir de diretórios específicos considerados suspeitos (por exemplo, C:\).
Nomes de Processos Suspeitos: Identifica processos com nomes que indicam potencial atividade maliciosa, como powershell, cmd.exe, wscript, entre outros.
Ignorar Processos Legítimos: Processos localizados em diretórios ignorados (como C:\Windows\, C:\Program Files\, etc.) ou que estão na lista de processos permitidos são excluídos da análise.
Gestão de Processos Suspeitos:


![image](https://github.com/user-attachments/assets/974df320-2ffa-4cd8-a966-e66d27177714)


Atenção no lado do servidor é criado um arquivo log.txt onde fica salvo as respostas enviada para o agente.

Suspensão de Processos: Quando um processo suspeito é identificado, o agente suspende sua execução temporariamente utilizando chamadas de sistema específicas do Windows (NtSuspendProcess).
Registro de Suspeitas: Detalhes do processo suspeito, incluindo nome, caminho, PID, endereços IP e hostname, são registrados localmente em um arquivo de log (log.txt) e enviados para um servidor central para avaliação.


![image](https://github.com/user-attachments/assets/24e15751-e523-44c6-b609-7dfe978bd11a)




Comunicação com o Servidor:

Mapeamento de Mensagens: Mantém um mapeamento de IDs de mensagens para processos suspeitos, garantindo que cada decisão recebida corresponda ao processo correto.
Tratamento de Respostas Automáticas: Em caso de perda de conexão com o servidor, o agente envia automaticamente a resposta "n" para todos os processos pendentes, finalizando-os.

Detecção de Perda de Conexão: Monitora a conexão com o servidor e detecta qualquer perda de conexão.
Reconexão Automática: Tenta reconectar automaticamente ao servidor em caso de falha na conexão.
Gestão de Mensagens Pendentes: Assegura que todas as mensagens pendentes sejam tratadas adequadamente em caso de desconexão.


