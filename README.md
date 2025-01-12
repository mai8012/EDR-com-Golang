EDR desenvolvido em Go (Golang) para monitoramento e resposta a atividades suspeitas em endpoints Windows.

O agente escaneia os processos em execução no sistema.

Detecta processos executados a partir de diretórios específicos considerados suspeitos.

Identifica processos com nomes que indicam potencial atividade maliciosa, como powershell, cmd.exe, wscript, entre outros.

Processos localizados em diretórios ignorados (como C:\Windows\, C:\Program Files\, etc.) ou que estão na lista de processos permitidos são excluídos da análise.

Gestão de Processos Suspeitos:


![image](https://github.com/user-attachments/assets/56c4e3b6-39a2-4173-b4bd-e0336653d57b)






Suspensão de Processos:

Quando um processo suspeito é identificado, o agente suspende sua execução temporariamente utilizando chamadas de sistema específicas do Windows (NtSuspendProcess).

Registro de Suspeitas: 

Detalhes do processo suspeito, incluindo nome, caminho, PID, endereços IP e hostname, são enviados para um servidor central para avaliação.


![image](https://github.com/user-attachments/assets/6a2901f9-f5f6-4385-a745-a8fafad126e2)





Servidor com autenticação:

![image](https://github.com/user-attachments/assets/926242b8-2fcc-410d-aad1-4ed744d3c231)





Atenção:ao iniciar o agent pela primeira vez:

![image](https://github.com/user-attachments/assets/4e13e16d-ba3d-4806-bb7d-fc8d9a8bd0f0)



Comunicação com o Servidor:

Atenção no lado do servidor é criado um arquivo log.json onde fica salvo as respostas enviada para o agente.


![image](https://github.com/user-attachments/assets/17279229-e08c-49a7-8f71-72ff6757ec72)





Mapeamento de Mensagens: 

Mantém um mapeamento de IDs de mensagens para processos suspeitos, garantindo que cada decisão recebida corresponda ao processo correto.

Tratamento de Respostas Automáticas: 

Em caso de perda de conexão com o servidor, o agente envia automaticamente a resposta "n" para todos os processos pendentes, finalizando-os.

Detecção de Perda de Conexão: 

Monitora a conexão com o servidor e detecta qualquer perda de conexão.

Reconexão Automática: 

Tenta reconectar automaticamente ao servidor em caso de falha na conexão.

Gestão de Mensagens Pendentes: 

Assegura que todas as mensagens pendentes sejam tratadas adequadamente em caso de desconexão.


