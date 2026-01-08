# Scan básico
nmap -p80,443 --script http-cors-permissive example.com

# Com paths customizados
nmap --script http-cors-permissive --script-args http-cors-permissive.paths="/api/admin,/v2/users" example.com

# Com timeout maior para servidores lentos
nmap --script http-cors-permissive --script-args http-cors-permissive.timeout=10000 example.com

# Sem testar subdomínios
nmap --script http-cors-permissive --script-args http-cors-permissive.check-subdomains=false example. com