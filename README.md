# mnscloud-agent

Agente local genérico da MNSCloud.

O agente roda no servidor onde existe algum recurso operacional da plataforma e se comunica com a API central por HTTPS outbound. Ele não recebe credenciais permanentes de storage; quando precisa executar uma ação sensível, a API entrega um job com autorização temporária e escopo mínimo.

A primeira capacidade operacional suportada pela API é `pabx`, usada para upload assíncrono de gravações geradas por Asterisk ou FreeSWITCH e para sincronização offline de media files do PABX. Essa capacidade não é configurada no instalador; ela é atribuída depois pela aplicação.

## Contrato

- Nome do produto/runtime: `mnscloud-agent`
- Pasta do projeto: `agent/`
- Dockerfile: `agent/Dockerfile`
- Container: `mnscloud-agent`
- Compose local: `/opt/mnscloud/agent/docker-compose.agent.yml`
- Configuração local: `/etc/mnscloud/agent/agent.conf`
- Estado local: `/var/lib/mnscloud/agent`
- Logs locais: `/var/log/mnscloud/agent`

## Instalação

```bash
scripts/install-agent.sh
```

O instalador detecta Docker/Compose, oferece instalar Docker quando necessário, gera ou reaproveita `/var/lib/mnscloud/agent/agent.uuid`, cria o `agent.conf` e sobe o container `mnscloud-agent`.

Depois da instalação, copie o UUID exibido pelo instalador e cadastre o agente na aplicação MNSCloud. A aplicação/API define as capacidades, recursos e comandos permitidos para esse agente.

## Segurança

- A comunicação é sempre outbound para a API.
- O agente não recebe engine, recurso ou função no instalador.
- A identidade local usa `agent.uuid` e, após ativação pela aplicação, `agent.token`.
- O agente lê apenas caminhos permitidos em `recordings.roots`.
- Uploads usam URL assinada de curta duração gerada pela API.
- Quando configurado com `recordings.delete_after_upload = true`, a cópia local
  é removida somente depois que o upload for aceito e confirmado na API.
- Media files offline são sincronizados para `media_files.roots` usando jobs
  temporários da API. O agente não recebe credenciais permanentes de storage.

Veja [agent.md](./agent.md) para a documentação completa do módulo e [SKILL.md](./SKILL.md) para o contrato de evolução técnica.
