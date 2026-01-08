description = [[
# Objetivo

Detectar e confirmar métodos HTTP perigosos habilitados em servidores web: PUT, DELETE,
TRACE, CONNECT, TRACK e PATCH. Esses métodos podem permitir upload de arquivos maliciosos,
exclusão de recursos, cross-site tracing (XST) e outras ações não autorizadas que
comprometem a segurança da aplicação.

## Riscos
- PUT: upload de arquivos maliciosos.
- DELETE: remoção indevida de recursos.
- TRACE/TRACK: XST; possível exposição de cookies/headers.
- CONNECT: criação de túneis/proxy e bypass de controles.
- PATCH: alteração não autorizada de recursos existentes.

## Abordagem de detecção
1. Consulta OPTIONS para identificar métodos anunciados em `Allow`/`Public`.
2. Testes ativos com cada método perigoso para confirmar se estão funcionais
	(observando respostas como 2xx/3xx, e bloqueios 405/501 quando corretamente negados).

## Escopo e pré-requisitos
- Porta HTTP/HTTPS acessível.
- Sem autenticação: foco em superfícies públicas.
- Alguns proxies/CDNs e WAFs podem alterar as respostas.

## Limitações
- Comportamento pode variar por rota (métodos habilitados apenas em caminhos específicos).
- Políticas condicionais por cabeçalhos podem afetar os resultados.

Referências (ver doc/referencias.md) 
]]
