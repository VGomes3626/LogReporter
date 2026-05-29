# Mini-SIEM (Local Log Analyzer)

Mini-SIEM é um projeto simples em Python para análise estática de arquivos de log locais (`access.log`). Ele detecta padrões comuns de ataques web (SQLi, XSS, força bruta) usando expressões regulares e oferece opções interativas para colar logs e exportar alertas.

## Arquivos principais
- `reporter.py` — analisador principal (leitura, detecção, exportação)
- `access.log` — arquivo de logs local (gerado/colado durante execução)

## Como usar
1. Abra um terminal na pasta do projeto.
2. Execute (Windows PowerShell):
```powershell
& ".\.venv\Scripts\python.exe" reporter.py
```
ou, se o virtualenv estiver ativado:
```powershell
python reporter.py
```
3. Siga o fluxo interativo para colar logs, analisar e — se houver alertas — exportar para TXT.

## Detectores
- SQL Injection: padrões `UNION SELECT`, `' OR 1=1`, `WAITFOR DELAY`, `SLEEP()`, comentários SQL e consultas empilhadas.
- XSS: procura por `<script>` (inclui versão codificada em URL como `%3Cscript%3E`).
- Força Bruta: conta requisições falhas a `/login.php` por IP e aciona alerta quando atinge o limiar (padrão: 3).



