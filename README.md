# Nmap NSE Security Scripts (PT-BR)

Coleção de scripts NSE (Nmap Scripting Engine) voltados para testes de segurança em aplicações web e APIs. Os scripts estão organizados por categoria (misconfiguration, information-disclosure, api-security, etc.) e focam em detecção de exposições comuns de forma prática para pentest.

## Estrutura

- `nse-scripts/` — scripts NSE e documentação
  - `api-security/` — endpoints e superfície de ataque de APIs
  - `authentication/` — problemas de autenticação/fluxos de login
  - `credential-access/` — exposição/enumeração relacionada a credenciais
  - `default-credentials/` — validação de credenciais padrão
  - `information-disclosure/` — vazamentos e superfície exposta (webmail, backups, DB tools)
  - `misconfiguration/` — CORS/headers/métodos perigosos/directory listing
  - `web-applications/` — checks voltados a aplicações web (inclui scripts OCovil)

Documentação detalhada:

- `nse-scripts/README.md` (visão geral)
- `nse-scripts/USAGE_GUIDE.md` (comandos de uso rápido)
- `nse-scripts/*/doc/README.md` (docs por categoria)