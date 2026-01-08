# Documento 1 — O que o script faz e como usar

## Objetivo

Detectar configurações CORS (Cross-Origin Resource Sharing) permissivas em serviços HTTP/HTTPS que podem representar riscos de segurança:

- Origem wildcard (`*`)
- Reflexão de origem (echo da origem enviada)
- Origem `null`
- Métodos HTTP perigosos
- Headers personalizados sem restrição

## Severidades Avaliadas

| Severidade | Critério |
|------------|----------|
| **CRITICAL** | Wildcard (`*`) com credenciais habilitadas |
| **HIGH** | Wildcard ou reflexão de origem com credenciais |
| **MEDIUM** | Reflexão sem credenciais, origem `null`, esquemas perigosos (file://, data://) |

## Como Funciona

1. **Envia requisições HTTP** com origens maliciosas simuladas (ex: `evil.com`, `null`, `file://`)
2. **Analisa cabeçalhos de resposta**:
    - `Access-Control-Allow-Origin`
    - `Access-Control-Allow-Credentials`
    - `Access-Control-Allow-Methods`
    - `Access-Control-Allow-Headers`
3. **Testa preflight** com requisições OPTIONS
4. **Identifica métodos perigosos**: DELETE, PUT, PATCH, TRACE
5. **Destaca headers sensíveis** permitidos sem restrição

## Uso Básico

```bash
# Scan básico em host específico
nmap --script http-cors-permissive -p 80,443 <target>

# Scan em range de portas HTTP
nmap --script http-cors-permissive -p 8000-9000 <target>

# Com verbosidade para detalhes
nmap --script http-cors-permissive -p 80 --script-args verbose=1 <target>
```

**Nota**: O script funciona automaticamente com `shortport.http`, detectando portas HTTP/HTTPS comuns (80, 443, 8080, 8443, etc.).