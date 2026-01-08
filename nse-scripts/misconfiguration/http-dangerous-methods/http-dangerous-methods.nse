local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tableaux = require "tableaux"
local vulns = require "vulns"

description = [[
Detecta métodos HTTP perigosos habilitados em servidores web, incluindo PUT, DELETE,
TRACE, CONNECT, TRACK e PATCH. Estes métodos podem permitir upload de arquivos maliciosos,
exclusão de recursos, cross-site tracing (XST) e outras ações não autorizadas que
comprometem a segurança da aplicação. 

O script realiza duas verificações: 
1. Consulta OPTIONS para identificar métodos anunciados
2. Testa cada método perigoso para confirmar se está realmente funcional

Referências: 
* OWASP:  https://owasp.org/www-community/vulnerabilities/Unsafe_HTTP_Methods
* CWE-650:  Trusting HTTP Permission Methods on the Server Side
]]

---
-- @usage 
-- nmap -p80,443 --script http-dangerous-methods <alvo>
-- nmap -p8080 --script http-dangerous-methods --script-args http-dangerous-methods.paths=/api/v1,/admin <alvo>
--
-- @args http-dangerous-methods.paths Caminhos extras (separados por vírgula) para testar
-- @args http-dangerous-methods.test-all Testa todos os métodos mesmo se não anunciados via OPTIONS (padrão:  false)
-- @args http-dangerous-methods.timeout Timeout para requisições HTTP em milissegundos (padrão: 10000)
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-dangerous-methods: 
-- |   VULNERABLE: 
-- |   Métodos HTTP Perigosos Habilitados
-- |     State: VULNERABLE
-- |     Risk factor: High
-- |     Description: 
-- |       O servidor web permite métodos HTTP perigosos que podem ser explorados
-- |       para comprometer a seguridade da aplicação. 
-- |     
-- |     Caminhos vulneráveis:
-- |     
-- |     Path: /uploads/
-- |       Allow Header: GET, POST, PUT, DELETE, OPTIONS
-- |       Métodos perigosos encontrados:
-- |         
-- |         Método: PUT
-- |           Severidade: HIGH
-- |           Risco: Permite upload de arquivos
-- |           Status de resposta: 200
-- |         
-- |         Método: DELETE
-- |           Severidade: HIGH
-- |           Risco: Permite exclusão de recursos
-- |_          Status de resposta: 204

author = "Gandalf, o cinzento"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "vuln"}

portrule = shortport.http

-- Paths comuns para teste
local default_paths = {
  "/",
  "/uploads/",
  "/upload/",
  "/files/",
  "/file/",
  "/api/",
  "/api/v1/",
  "/admin/",
  "/test/",
  "/webdav/",
  "/dav/",
  "/rest/",
  "/services/"
}

-- Definição de métodos perigosos com severidade e riscos
local dangerous_methods = {
  {method = "PUT", severity = "HIGH", risk = "Permite upload de arquivos arbitrários"},
  {method = "DELETE", severity = "HIGH", risk = "Permite exclusão de recursos"},
  {method = "TRACE", severity = "MEDIUM", risk = "Possibilita XST (Cross-Site Tracing)"},
  {method = "TRACK", severity = "MEDIUM", risk = "Possibilita XST (Cross-Site Tracing)"},
  {method = "CONNECT", severity = "MEDIUM", risk = "Pode permitir proxy HTTP não autorizado"},
  {method = "PATCH", severity = "MEDIUM", risk = "Permite modificação parcial de recursos"},
  {method = "PROPFIND", severity = "LOW", risk = "Pode expor estrutura de diretórios (WebDAV)"},
  {method = "PROPPATCH", severity = "MEDIUM", risk = "Permite modificar propriedades (WebDAV)"},
  {method = "MKCOL", severity = "MEDIUM", risk = "Permite criar coleções/diretórios (WebDAV)"},
  {method = "COPY", severity = "MEDIUM", risk = "Permite copiar recursos (WebDAV)"},
  {method = "MOVE", severity = "MEDIUM", risk = "Permite mover recursos (WebDAV)"},
  {method = "LOCK", severity = "LOW", risk = "Permite bloquear recursos (WebDAV)"},
  {method = "UNLOCK", severity = "LOW", risk = "Permite desbloquear recursos (WebDAV)"}
}

-- Função auxiliar para trimming de strings
local function trim(s)
  return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

-- Constrói lista de paths a partir dos padrões + argumentos do usuário
local function build_paths()
  local paths = {}
  local seen = {}
  
  -- Adiciona paths padrão
  for _, p in ipairs(default_paths) do
    if not seen[p] then
      paths[#paths + 1] = p
      seen[p] = true
    end
  end
  
  -- Adiciona paths customizados
  local arg = stdnse.get_script_args(SCRIPT_NAME .. ".paths")
  if arg then
    for token in string.gmatch(arg, "[^,]+") do
      local cleaned = trim(token)
      if cleaned ~= "" then
        -- Garante que começa com /
        if cleaned: sub(1, 1) ~= "/" then
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

-- Verifica métodos permitidos via OPTIONS
local function check_options(host, port, path)
  local options = {
    timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 10000
  }
  
  local resp = http.generic_request(host, port, "OPTIONS", path, options)
  
  if not resp or not resp.header then
    return nil
  end
  
  -- Verifica header Allow (RFC 2616) e Public (menos comum)
  local allow = resp.header["allow"] or resp.header["public"]
  if not allow then
    return nil
  end
  
  return allow
end

-- Testa se um método HTTP específico está funcional
local function test_method(host, port, path, method)
  local options = {
    timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME ..  ".timeout")) or 10000,
    header = {
      ["Content-Type"] = "application/octet-stream"
    }
  }
  
  -- Para PUT, envia um corpo mínimo
  if method == "PUT" then
    options.content = "test"
  end
  
  local resp = http.generic_request(host, port, method, path, options)
  
  if not resp then
    return false, nil
  end
  
  -- Métodos aceitos: 2xx e 3xx
  if resp.status >= 200 and resp.status < 400 then
    return true, resp.status
  end
  
  -- 405 = Method Not Allowed
  if resp. status == 405 then
    return false, 405
  end
  
  -- 501 = Not Implemented
  if resp.status == 501 then
    return false, 501
  end
  
  -- Outros códigos podem indicar método aceito mas com erro de autenticação/validação
  -- 401 (Unauthorized) e 403 (Forbidden) indicam que o método é reconhecido
  if resp.status == 401 or resp.status == 403 then
    return true, resp.status, "Requer autenticação/autorização"
  end
  
  return false, resp.status
end

-- Parse do header Allow/Public
local function parse_allowed_methods(allow_header)
  if not allow_header then
    return {}
  end
  
  local methods = {}
  -- Match palavras em maiúsculas (métodos HTTP)
  for method in allow_header:gmatch("[A-Z]+") do
    methods[method] = true
  end
  
  return methods
end

-- Determina severidade máxima encontrada
local function get_max_severity(findings)
  local severity_order = {HIGH = 3, MEDIUM = 2, LOW = 1}
  local max_severity = "LOW"
  local max_value = 0
  
  for _, finding in ipairs(findings) do
    local value = severity_order[finding.severity] or 0
    if value > max_value then
      max_value = value
      max_severity = finding.severity
    end
  end
  
  return max_severity
end

action = function(host, port)
  local test_all = stdnse.get_script_args(SCRIPT_NAME .. ".test-all")
  local vulnerable_paths = {}
  local paths = build_paths()
  
  stdnse.debug1("Testando %d paths", #paths)

  for _, path in ipairs(paths) do
    stdnse.debug2("Verificando path: %s", path)
    
    local allow_header = check_options(host, port, path)
    local allowed_methods = {}
    
    if allow_header then
      stdnse.debug2("OPTIONS retornou:  %s", allow_header)
      allowed_methods = parse_allowed_methods(allow_header)
    else
      stdnse.debug2("OPTIONS não retornou métodos permitidos")
    end
    
    local dangerous_found = {}
    
    for _, method_info in ipairs(dangerous_methods) do
      local should_test = test_all or allowed_methods[method_info.method]
      
      if should_test then
        stdnse.debug2("Testando método %s em %s", method_info.method, path)
        local works, status, note = test_method(host, port, path, method_info. method)
        
        if works then
          local finding = {
            method = method_info. method,
            severity = method_info.severity,
            risk = method_info.risk,
            response_status = status
          }
          
          if note then
            finding.note = note
          end
          
          -- Adiciona info se foi anunciado via OPTIONS
          if not allowed_methods[method_info.method] then
            finding.announced = false
            finding.note = (finding.note or "") .. " (Não anunciado em OPTIONS)"
          else
            finding.announced = true
          end
          
          dangerous_found[#dangerous_found + 1] = finding
          stdnse.debug1("VULNERÁVEL: %s %s - Status %d", method_info.method, path, status)
        elseif allowed_methods[method_info.method] and not test_all then
          -- Anunciado mas não confirmado
          local finding = {
            method = method_info.method,
            severity = method_info.severity,
            risk = method_info.risk,
            announced = true,
            confirmed = false,
            note = string.format("Anunciado em OPTIONS mas retornou status %d", status or 0)
          }
          dangerous_found[#dangerous_found + 1] = finding
          stdnse.debug2("Anunciado mas não confirmado: %s %s", method_info.method, path)
        end
      end
    end
    
    if #dangerous_found > 0 then
      local entry = {
        path = path,
        allow_header = allow_header or "Não disponível",
        dangerous_methods = dangerous_found,
        severity = get_max_severity(dangerous_found)
      }
      vulnerable_paths[#vulnerable_paths + 1] = entry
    end
  end

  if #vulnerable_paths == 0 then
    stdnse.debug1("Nenhum método perigoso encontrado")
    return nil
  end

  -- Formata saída usando biblioteca vulns
  local vuln_table = {
    title = "Métodos HTTP Perigosos Habilitados",
    state = vulns.STATE. VULN,
    risk_factor = "High",
    description = [[
O servidor web permite métodos HTTP perigosos que podem ser explorados
para comprometer a segurança da aplicação.  Métodos como PUT e DELETE podem
permitir upload de arquivos maliciosos ou exclusão de recursos.  TRACE/TRACK
podem ser usados em ataques XST (Cross-Site Tracing).
    ]],
    references = {
      'https://owasp.org/www-community/vulnerabilities/Unsafe_HTTP_Methods',
      'https://cwe.mitre.org/data/definitions/650.html'
    }
  }
  
  -- Adiciona informações dos paths vulneráveis
  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local vuln_obj = report:make_output(vuln_table)
  
  -- Adiciona detalhes dos paths
  vuln_obj.paths = vulnerable_paths
  
  return vuln_obj
end