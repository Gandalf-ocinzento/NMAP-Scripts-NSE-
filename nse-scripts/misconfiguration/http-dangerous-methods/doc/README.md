# http-dangerous-methods (NSE)

Detecta métodos HTTP perigosos habilitados (PUT, DELETE, TRACE, CONNECT, TRACK, PATCH) e confirma se estão funcionalmente ativos via testes controlados.

Documentação:
- [Objetivo](objetivo.md)
- [Uso (Comandos)](comandos.md)
- [Exemplos de saída](exemplos.md)
- [Remediação](remediacao.md)
- [Referências](referencias.md)

Resumo da abordagem:
- Consulta `OPTIONS` para descobrir métodos anunciados (cabeçalhos `Allow`/`Public`).
- Executa requisições com cada método perigoso e interpreta respostas (2xx/3xx = potencialmente funcional; 405/501 = corretamente negado).

Notas:
- Escopo público, sem autenticação.
- Proxies/CDNs/WAFs podem mascarar ou alterar comportamento.
