# Agent Module Skill

Use este contrato ao alterar o módulo `agent/`.

## Fonte de Verdade

- Runtime: `agent/main.ts`
- Dockerfile: `agent/Dockerfile`
- Instalador: `scripts/install-agent.sh`
- Documentação: `agent/agent.md`
- API runtime: `api/routes/agentRoute.ts`, `api/controllers/agentController.ts`, `api/services/agentRuntimeService.ts`
- Monitoramento: `MonitoringAgent`, `MonitoringAgentCapability`, `MonitoringAgentAssignment`

## Nomenclatura Obrigatória

- Produto: `mnscloud-agent`
- Pasta: `agent`
- Container: `mnscloud-agent`
- Compose local: `docker-compose.agent.yml`
- Configuração local: `agent.conf`

Nunca criar nomes, rotas ou containers específicos por tecnologia ou função. O contrato deste módulo é sempre genérico.

## Modelo

O agente é genérico. Recursos específicos entram por:

- `capabilities`: exemplo `pabx`
- `assignments`: exemplo `voip_pabx_server`

Não adicionar acoplamento direto de recurso na identidade principal do agente.

## Segurança

- Comunicação apenas outbound por HTTPS.
- O instalador não define engine, recurso ou função.
- O agente só recebe capacidades e assignments pela aplicação/API.
- Token do agente fica em `/var/lib/mnscloud/agent/agent.token`.
- Credenciais permanentes de storage ficam somente na API.
- Jobs usam autorização temporária, preferencialmente URL assinada.

## Checklist

- Atualizar documentação quando mudar contrato do agente.
- Rodar busca de resíduos por nomes antigos.
- Validar `scripts/install-agent.sh` com `bash -n`.
- Validar `agent/main.ts` com `deno check`.
