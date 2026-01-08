local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local nmap = require "nmap"

description = [[
Detecta configurações CORS (Cross-Origin Resource Sharing) permissivas que permitem
acesso de qualquer origem (*), ou que refletem a origem da requisição sem validação. 

CORS mal configurado permite que sites maliciosos façam requisições autenticadas
em nome do usuário, possibilitando roubo de dados e ações não autorizadas. 

Vulnerabilidades detectadas:
- Wildcard (*) com credenciais habilitadas (CRÍTICO)
- Reflexão de origem sem validação (ALTO)
- Wildcard sem validação de esquema (ALTO)
- Origem 'null' permitida (MÉDIO)
- Métodos/Headers perigosos permitidos (MÉDIO)
]]

---
-- @usage nmap -p80,443 --script http-cors-permissive <alvo>
-- @args http-cors-permissive.paths Caminhos extras (separados por vírgula) para testar. 
-- @args http-cors-permissive.timeout Timeout para cada requisição em ms (padrão: 5000)
-- @args http-cors-permissive.check-subdomains Testa variações de subdomínio (padrão: true)
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | http-cors-permissive: 
-- |   VULNERABLE: 
-- |   Configuração CORS Permissiva Detectada
-- |     State: VULNERABLE
-- |     Risk factor: High
-- |     Description: 
-- |       O servidor possui configuração CORS que permite requisições cross-origin
-- |       de origens não confiáveis, permitindo potencial roubo de dados. 
-- |     
-- |     Vulnerabilidades encontradas:
-- |       
-- |       [CRITICAL] /api/v1
-- |         Issue:  Wildcard com credenciais habilitadas
-- |         Access-Control-Allow-Origin: *
-- |         Access-Control-Allow-Credentials: true
-- |         Risk:  Permite qualquer site fazer requisições autenticadas
-- |       
-- |       [HIGH] /api/users
-- |         Issue:  CORS reflete origem sem validação
-- |         Test Origin: https://evil.com
-- |         Access-Control-Allow-Origin: https://evil.com
-- |         Access-Control-Allow-Credentials: true
-- |         Allowed Methods: GET, POST, PUT, DELETE
-- |         Allowed Headers: Authorization, X-API-Key
-- |     
-- |     References:
-- |       https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny
-- |_      https://portswigger.net/web-security/cors

author = "Gandalf, o cinzento"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "vuln"}

portrule = shortport.http

local default_paths = {
  "/",
  "/api",
  "/api/v1",
  "/api/v2",
  "/api/v3",
  "/rest",
  "/graphql",
  "/api/users",
  "/api/data",
  "/api/admin",
  "/api/auth",
  "/api/me",
  "/api/profile"
}

local test_origins = {
  "https://evil.com",
  "https://attacker.com",
  "http://malicious.net",
  "null",
  "file://",
  -- Testes com esquemas diferentes
  "data: text/html,<script>alert(1)</script>",
}

local dangerous_methods = {
  "PUT", "DELETE", "PATCH", "TRACE", "CONNECT"
}

local dangerous_headers = {
  "Authorization", "X-API-Key", "X-Auth-Token", 
  "Cookie", "X-CSRF-Token", "X-Requested-With"
}

---
-- Remove espaços em branco no início e fim
local function trim(s)
  return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

---
-- Constrói lista de paths para testar
local function build_paths()
  local paths = {}
  local seen = {}
  
  for _, p in ipairs(default_paths) do
    if not seen[p] then
      paths[#paths + 1] = p
      seen[p] = true
    end
  end
  
  local arg = stdnse.get_script_args(SCRIPT_NAME .. ".paths")
  if arg then
    for token in string.gmatch(arg, "[^,]+") do
      local cleaned = trim(token)
      if cleaned ~= "" then
        if cleaned:sub(1, 1) ~= "/" then
          cleaned = "/" .. cleaned
        end
        if not seen[cleaned] then
          paths[#paths + 1] = cleaned
          seen[cleaned] = true
        end
      end
    end
  end
  
  return paths
end

---
-- Gera variações de origem baseadas no host alvo
local function generate_origin_variations(host)
  local variations = {}
  local hostname = host. targetname or host.ip
  
  -- Testa subdomínios do próprio alvo
  table.insert(variations, string.format("https://evil.%s", hostname))
  table.insert(variations, string.format("https://%s. evil.com", hostname))
  table.insert(variations, string.format("http://%s", hostname))
  
  return variations
end

---
-- Verifica se um método é perigoso
local function is_dangerous_method(method)
  for _, dm in ipairs(dangerous_methods) do
    if method and method: upper():find(dm) then
      return true
    end
  end
  return false
end

---
-- Verifica se um header é sensível
local function contains_dangerous_header(headers_str)
  if not headers_str then return false end
  
  local found = {}
  for _, dh in ipairs(dangerous_headers) do
    if headers_str:lower():find(dh:lower()) then
      table.insert(found, dh)
    end
  end
  
  return #found > 0 and found or false
end

---
-- Realiza teste CORS básico
local function check_cors(host, port, path, origin, timeout)
  local options = {
    header = {
      ["Origin"] = origin,
      ["User-Agent"] = "Mozilla/5.0 CORS-Scanner"
    },
    timeout = timeout
  }
  
  local resp = http.get(host, port, path, options)
  
  if not resp or not resp. header then
    return nil
  end
  
  -- Captura todos os headers CORS relevantes (case-insensitive)
  local acao, acac, acah, acam, acma, aceh
  for key, value in pairs(resp. header) do
    local lower_key = key:lower()
    if lower_key == "access-control-allow-origin" then
      acao = value
    elseif lower_key == "access-control-allow-credentials" then
      acac = value
    elseif lower_key == "access-control-allow-headers" then
      acah = value
    elseif lower_key == "access-control-allow-methods" then
      acam = value
    elseif lower_key == "access-control-max-age" then
      acma = value
    elseif lower_key == "access-control-expose-headers" then
      aceh = value
    end
  end
  
  if not acao then
    return nil
  end
  
  local result = {
    allow_origin = acao,
    allow_credentials = acac or "not set",
    allow_headers = acah,
    allow_methods = acam,
    max_age = acma,
    expose_headers = aceh,
    status_code = resp.status
  }
  
  -- CRÍTICO: Wildcard com credenciais
  if acao == "*" and acac and acac: lower() == "true" then
    result.severity = "CRITICAL"
    result.issue = "Wildcard com credenciais habilitadas (configuração inválida mas perigosa)"
    return result
  end
  
  -- ALTO: Wildcard sem credenciais
  if acao == "*" then
    result.severity = "HIGH"
    result.issue = "CORS permite qualquer origem (*)"
    return result
  end
  
  -- ALTO: Reflexão de origem com credenciais
  if acao == origin and acac and acac:lower() == "true" then
    result.severity = "HIGH"
    result.issue = "CORS reflete origem sem validação (com credenciais)"
    return result
  end
  
  -- MÉDIO: Reflexão de origem sem credenciais
  if acao == origin then
    result.severity = "MEDIUM"
    result.issue = "CORS reflete origem sem validação (sem credenciais)"
    return result
  end
  
  -- MÉDIO: Origem 'null' permitida
  if acao == "null" and origin == "null" then
    result.severity = "MEDIUM"
    result.issue = "CORS permite origem 'null' (explorável via sandbox)"
    return result
  end
  
  -- BAIXO: Esquemas perigosos
  if origin:match("^file://") or origin:match("^data:") then
    if acao == origin then
      result.severity = "MEDIUM"
      result.issue = "CORS permite esquemas perigosos"
      return result
    end
  end
  
  return nil
end

---
-- Verifica resposta OPTIONS (preflight)
local function check_options(host, port, path, timeout)
  local options = {
    header = {
      ["Origin"] = "https://evil.com",
      ["Access-Control-Request-Method"] = "DELETE",
      ["Access-Control-Request-Headers"] = "Authorization, X-API-Key"
    },
    timeout = timeout
  }
  
  local resp = http.generic_request(host, port, "OPTIONS", path, options)
  
  if not resp or not resp.header then
    return nil
  end
  
  local methods, headers, max_age, acao
  for key, value in pairs(resp.header) do
    local lower_key = key: lower()
    if lower_key == "access-control-allow-methods" then
      methods = value
    elseif lower_key == "access-control-allow-headers" then
      headers = value
    elseif lower_key == "access-control-max-age" then
      max_age = value
    elseif lower_key == "access-control-allow-origin" then
      acao = value
    end
  end
  
  if not methods and not headers and not acao then
    return nil
  end
  
  local result = {
    methods = methods or "not set",
    headers = headers or "not set",
    max_age = max_age or "not set",
    allow_origin = acao
  }
  
  -- Verifica métodos perigosos
  if methods and is_dangerous_method(methods) then
    result.dangerous_methods = true
  end
  
  -- Verifica headers sensíveis
  local dangerous = contains_dangerous_header(headers)
  if dangerous then
    result.dangerous_headers = dangerous
  end
  
  return result
end

---
-- Formata saída no estilo vulnerabilidade
local function format_vuln_output(vulnerabilities)
  local vuln = {
    title = "Configuração CORS Permissiva Detectada",
    state = "VULNERABLE",
    risk_factor = "High",
    description = [[
O servidor possui configuração CORS que permite requisições cross-origin
de origens não confiáveis, permitindo potencial roubo de dados.]],
    findings = {}
  }
  
  for _, v in ipairs(vulnerabilities) do
    local finding = {
      string.format("[%s] %s", v. severity, v.path),
      string.format("  Issue: %s", v.issue),
      string.format("  Access-Control-Allow-Origin: %s", v.allow_origin),
    }
    
    if v.test_origin then
      table.insert(finding, string.format("  Test Origin: %s", v.test_origin))
    end
    
    if v.allow_credentials ~= "not set" then
      table.insert(finding, string. format("  Access-Control-Allow-Credentials:  %s", v.allow_credentials))
    end
    
    if v.allowed_methods and v.allowed_methods ~= "not set" then
      table.insert(finding, string. format("  Allowed Methods: %s", v.allowed_methods))
      if v.dangerous_methods then
        table.insert(finding, "  ⚠ Métodos perigosos detectados!")
      end
    end
    
    if v.allowed_headers and v.allowed_headers ~= "not set" then
      table.insert(finding, string.format("  Allowed Headers: %s", v.allowed_headers))
      if v.dangerous_headers then
        table.insert(finding, string.format("  ⚠ Headers sensíveis:  %s", table.concat(v.dangerous_headers, ", ")))
      end
    end
    
    if v.max_age and v. max_age ~= "not set" then
      table.insert(finding, string.format("  Max Age: %s segundos", v.max_age))
    end
    
    if v.expose_headers then
      table.insert(finding, string.format("  Expose Headers: %s", v.expose_headers))
    end
    
    table.insert(finding, "") -- Linha vazia entre findings
    table.insert(vuln.findings, table.concat(finding, "\n"))
  end
  
  vuln.references = {
    "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
    "https://portswigger.net/web-security/cors",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
  }
  
  return vuln
end

action = function(host, port)
  local vulnerable = {}
  local paths = build_paths()
  local timeout = tonumber(stdnse. get_script_args(SCRIPT_NAME ..  ".timeout")) or 5000
  local check_subdomains = stdnse.get_script_args(SCRIPT_NAME .. ".check-subdomains")
  
  -- Adiciona variações de origem se habilitado
  local all_origins = {}
  for _, o in ipairs(test_origins) do
    table.insert(all_origins, o)
  end
  
  if check_subdomains ~= "false" then
    for _, o in ipairs(generate_origin_variations(host)) do
      table.insert(all_origins, o)
    end
  end
  
  stdnse.debug1("Testando %d paths em %d origens", #paths, #all_origins)

  for _, path in ipairs(paths) do
    stdnse.debug2("Testando path: %s", path)
    
    for _, origin in ipairs(all_origins) do
      local result = check_cors(host, port, path, origin, timeout)
      
      if result then
        stdnse.debug1("Vulnerabilidade encontrada em %s com origem %s", path, origin)
        
        local entry = {
          path = path,
          test_origin = origin,
          severity = result.severity,
          issue = result.issue,
          allow_origin = result.allow_origin,
          allow_credentials = result.allow_credentials,
          status_code = result.status_code
        }
        
        -- Adiciona informações do preflight
        local preflight = check_options(host, port, path, timeout)
        if preflight then
          entry.allowed_methods = preflight.methods
          entry.allowed_headers = preflight.headers
          entry.max_age = preflight.max_age
          entry.dangerous_methods = preflight.dangerous_methods
          entry.dangerous_headers = preflight.dangerous_headers
        end
        
        -- Adiciona outros headers CORS encontrados
        if result.allow_methods then
          entry.allowed_methods = result.allow_methods
        end
        if result. allow_headers then
          entry. allowed_headers = result.allow_headers
        end
        if result.expose_headers then
          entry.expose_headers = result.expose_headers
        end
        if result.max_age then
          entry.max_age = result. max_age
        end
        
        table.insert(vulnerable, entry)
        
        -- Break apenas se for CRITICAL ou HIGH para não duplicar
        if result.severity == "CRITICAL" or result.severity == "HIGH" then
          break
        end
      end
    end
  end

  if #vulnerable == 0 then
    return nil
  end
  
  -- Ordena por severidade
  local severity_order = {CRITICAL = 1, HIGH = 2, MEDIUM = 3, LOW = 4}
  table.sort(vulnerable, function(a, b)
    return severity_order[a.severity] < severity_order[b.severity]
  end)

  return format_vuln_output(vulnerable)
end