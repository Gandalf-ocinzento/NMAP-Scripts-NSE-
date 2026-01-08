# Comandos NMAP - HTTP CORS Permissive

## Scans Básicos

### Scan padrão (HTTP/HTTPS comuns)
```bash
nmap -p80,443 --script http-cors-permissive <alvo>
```

### Scan em múltiplas portas HTTP típicas
```bash
nmap -p80,443,8080,8443 --script http-cors-permissive <alvo>
```

### Combinar com detecção de serviço/versão
```bash
nmap -sV -p80,443 --script http-cors-permissive <alvo>
```

## Configurações Personalizadas

### Definir timeout por requisição (ms)
```bash
nmap -p80,443 --script http-cors-permissive --script-args http-cors-permissive.timeout=7000 <alvo>
```

### Adicionar caminhos extras (vírgula)
```bash
nmap -p80,443 --script http-cors-permissive --script-args http-cors-permissive.paths="/minha/api,/outra/rota" <alvo>
```

### Desabilitar teste de variações de subdomínio
```bash
nmap -p80,443 --script http-cors-permissive --script-args http-cors-permissive.check-subdomains=false <alvo>
```

## Saída Esperada

- Lista de achados por rota testada
- Severidade e issue
- Cabeçalhos CORS relevantes, métodos/headers permitidos
- Avisos de métodos/headers perigosos