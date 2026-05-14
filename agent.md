# MNSCloud Agent

## Visão Geral

`mnscloud-agent` é o agente local genérico da plataforma. Ele não é um agente PABX por nome; PABX é apenas a primeira capacidade suportada. O mesmo runtime deve aceitar novas capacidades no futuro, como `db`, `api`, `server`, `sbc` ou `softswitch`, sem mudar nome de container, pasta, configuração ou API pública.

## Arquitetura

O agente roda próximo ao recurso operacional. No caso atual, ele roda no host onde Asterisk ou FreeSWITCH gravam arquivos de áudio. A API central controla identidade, permissões, capacidades, assignments e jobs.

Fluxo:

1. O instalador cria `/etc/mnscloud/agent/agent.conf`.
2. O instalador gera ou reaproveita `/var/lib/mnscloud/agent/agent.uuid`.
3. O operador cadastra o UUID na aplicação MNSCloud.
4. A aplicação/API ativa o agente, define seu tenant, token, capacidades e assignments.
5. O agente envia heartbeat em `POST /api/v1/agent/heartbeat` quando `agent.token` existir.
6. O agente busca jobs em `POST /api/v1/agent/jobs/lease`.
7. Para gravações, a API fornece URL assinada temporária.
8. O agente faz upload e confirma ou falha o job.

## Configuração

Arquivo canônico local:

```text
/etc/mnscloud/agent/agent.conf
```

Formato:

```ini
[agent]
name = asterisk-dev1
hostname = asterisk-dev1.local
api_base = https://dev1.publichost.cloud
version = 0.1.0
poll_interval_ms = 15000
heartbeat_interval_ms = 60000

[identity]
agent_uuid_file = /var/lib/mnscloud/agent/agent.uuid
agent_token_file = /var/lib/mnscloud/agent/agent.token

[recordings]
roots = /recordings/freeswitch,/recordings/asterisk
mounts = /var/lib/freeswitch/recordings=/recordings/freeswitch,/var/spool/asterisk/monitor=/recordings/asterisk
delete_after_upload = true

[media_files]
roots = /media-files
mounts = /var/lib/mnscloud/pabx/media-files=/media-files
```

Não usar `.env` para o agente. Seguir `agent.conf` para configuração local e `/var/lib/mnscloud/agent` para identidade/estado.

## Banco de Dados

Modelo canônico:

- `MonitoringAgent`: identidade, token, hostname, versão, status, heartbeat e tenant.
- `MonitoringAgentCapability`: capacidades do agente, como `pabx`.
- `MonitoringAgentAssignment`: recursos atribuídos ao agente, como `voip_pabx_server`.

Não adicionar colunas de tipo ou recurso diretamente em `MonitoringAgent`. A relação deve ser sempre por capability e assignment.

## API

Endpoints canônicos:

- `POST /api/v1/agent/heartbeat`
- `POST /api/v1/agent/jobs/lease`
- `POST /api/v1/agent/jobs/:uuid/complete`
- `POST /api/v1/agent/jobs/:uuid/fail`

Headers canônicos:

- `Authorization: Bearer <token>`
- `X-MNSCloud-Agent-UUID: <uuid>`

Não criar endpoints específicos por capacidade. O PABX é tratado por payload/capability dentro do agente genérico.

## Docker

Container:

```text
mnscloud-agent
```

Imagem local:

```text
mnscloud/agent:local
```

O container deve ser restrito:

- `read_only: true`
- `network_mode: host`
- `cap_drop: [ALL]`
- `security_opt: no-new-privileges:true`
- `/etc/mnscloud/agent` montado somente leitura
- `/var/lib/mnscloud/agent` gravável para `agent.uuid` e `agent.token`
- diretórios de gravação montados somente nos roots configurados e com escrita limitada
  para remover a cópia local após upload confirmado

## Capacidade PABX

Quando o agente recebe a capacidade `pabx` e assignment para um `voip_pabx_server`, ele faz:

- heartbeat do host;
- lease de jobs de upload de gravações;
- lease de jobs de sincronização offline de media files;
- leitura de arquivo local validada por path allowlist;
- upload por URL assinada;
- confirmação ou falha do job.
- remoção da gravação local quando `recordings.delete_after_upload = true` e o
  upload já tiver sido confirmado pela API.

Asterisk e FreeSWITCH gravam primeiro em filesystem local. O agente é responsável por mover a gravação para storage externo quando o PABX estiver configurado para storage.

Para media files offline, a API entrega um job `media_file_sync` com ação `sync`
ou `delete`. Na ação `sync`, o agente baixa o arquivo por URL temporária
assinada ou por endpoint autenticado do próprio job, grava atomicamente no
diretório permitido e confirma. Na ação `delete`, remove a cópia local e confirma.
Credenciais permanentes de storage continuam somente na API.

## Regras de Evolução

- Não criar nomes específicos por tecnologia ou função.
- Não usar `.env` como contrato de configuração do agente.
- Não colocar credencial permanente de storage no agente.
- Novas funções entram como capabilities e assignments.
- A interface de monitoramento deve ler `MonitoringAgent` e suas relações, não tabelas específicas de cada recurso.
