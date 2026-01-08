# Remediação

## Apache (HTTPD)
- Desabilitar TRACE:
  - `TraceEnable off`
- Restringir métodos por diretório/rota:
```
<Directory "/var/www/html">
  <LimitExcept GET POST HEAD>
    Require all denied
  </LimitExcept>
</Directory>
```

## Nginx
- Retornar 405 para métodos perigosos:
```
if ($request_method ~* (TRACE|DELETE|TRACK|CONNECT|PATCH|PUT)) { 
  return 405; 
}
```
- Em `location` específico, permitir apenas GET/POST/HEAD.

## IIS
- Em `web.config`:
```
<system.webServer>
  <security>
    <requestFiltering>
      <verbs>
        <add verb="TRACE" allowed="false" />
        <add verb="DELETE" allowed="false" />
        <add verb="PUT" allowed="false" />
        <add verb="CONNECT" allowed="false" />
        <add verb="PATCH" allowed="false" />
      </verbs>
    </requestFiltering>
  </security>
</system.webServer>
```

Valide após a mudança executando novamente o script.
