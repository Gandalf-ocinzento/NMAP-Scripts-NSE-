# Exemplos de Saída

## Host com TRACE e PUT habilitados
Host: 10.0.0.5  
Porta: 80/tcp

- Métodos anunciados: GET, POST, HEAD, TRACE, PUT
- Testes:
  - TRACE: 200 OK (funcional)
  - PUT: 201 Created (upload permitido)
  - DELETE: 405 Method Not Allowed
  - CONNECT: 501 Not Implemented
  - PATCH: 405 Method Not Allowed

## Host sem métodos perigosos
Host: site.example.com  
Porta: 443/tcp

- Métodos anunciados: GET, POST, HEAD
- Testes: todos retornam 405/501 (não funcionais)
