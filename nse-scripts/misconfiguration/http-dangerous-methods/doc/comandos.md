# Uso básico
nmap -p80 --script http-dangerous-methods example.com

# Com paths customizados
nmap -p8080 --script http-dangerous-methods --script-args http-dangerous-methods.paths=/api/v2,/graphql example.com

# Teste agressivo (todos os métodos)
nmap -p443 --script http-dangerous-methods --script-args http-dangerous-methods.test-all=true example. com

# Com timeout customizado
nmap -p80 --script http-dangerous-methods --script-args http-dangerous-methods.timeout=5000 example. com