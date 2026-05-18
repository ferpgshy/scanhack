# 🛡️ ScanHack — SecurityAudit

> **Auditoria de segurança local para Windows** — identifica processos suspeitos, conexões maliciosas, credenciais expostas e indicadores de comprometimento (IOC), com interface web em tempo real.

---

## 📸 Interface

| Tela de progresso | Relatório de auditoria |
|:-:|:-:|
| Interface dark com radar de scan animado | Dashboard de risco com seção de credenciais |

---

## ✨ Funcionalidades

| # | Seção | O que coleta |
|---|-------|-------------|
| 1 | **Sistema** | SO, build, BIOS, uptime, último reboot |
| 2 | **Conexões de rede** | TCP/UDP ativas, IPs externos, conexões suspeitas |
| 3 | **Processos** | Todos os processos, assinatura digital, empresa, path |
| 4 | **Persistência** | Run keys de registro, tarefas agendadas, serviços em paths incomuns |
| 5 | **Usuários** | Contas locais, grupo Administradores, senhas que nunca expiram |
| 6 | **Credenciais e senhas** | Windows Credential Manager, Windows Vault (senha parcial), bancos de senhas de browsers |
| 7 | **Eventos de segurança** | Falhas de logon (4625), contas criadas (4720), admins adicionados (4732), log limpo (1102) |
| 8 | **Arquivos suspeitos** | Scripts sem assinatura em Temp, Downloads e ProgramData |
| 9 | **Portas e DNS** | Portas em escuta, cache DNS |

### Extras
- ⚡ **Interface web em tempo real** (`progress.html`) — progresso passo a passo com radar animado
- 🔐 **Seção de senhas estilo Apple** — URL, login e senha parcial (`s●●●●o`)
- 🚨 **Score de risco** — BAIXO / MÉDIO / ALTO / CRÍTICO com pontuação
- 📊 **Relatório HTML dark** — design profissional, collapsible sections, back-to-top
- 📄 **Relatório TXT** — resumo rápido de todos os contadores
- 🔇 **Execução silenciosa** — zero janelas visíveis via `run.vbs`

---

## 🚀 Como usar

### Modo silencioso (recomendado)
```
run.vbs
```
Não abre nenhum terminal. Apenas o UAC aparece → browser abre automaticamente com o progresso.

### Modo debug (com terminal)
```
run.bat
```
Mostra o terminal com output em tempo real. Útil para diagnóstico.

---

## 📋 Requisitos

| Requisito | Versão |
|-----------|--------|
| Windows | 10 / 11 |
| PowerShell | 7+ (`pwsh`) |
| Permissão | Administrador (UAC) |
| Browser | Qualquer (abre automaticamente) |

> PowerShell 7: [download aqui](https://github.com/PowerShell/PowerShell/releases/latest)

---

## 📁 Estrutura

```
scanhack/
├── SecurityAudit.ps1   # Script principal de auditoria
├── progress.html       # Interface web de progresso (dark, animada)
├── run.vbs             # Launcher silencioso (sem janelas)
├── run.bat             # Launcher com terminal (debug)
└── reports/
    └── YYYY-MM-DD/
        └── audit_HH-mm.html    # Relatório HTML gerado
        └── audit_HH-mm.txt     # Resumo TXT gerado
```

---

## 🔒 Seção de Credenciais

A seção **Credenciais e senhas** detecta:

1. **Windows Credential Manager** — credenciais web e genéricas armazenadas
2. **Windows Vault** — senhas de aplicativos (exibe senha parcial mascarada: `s●●●●●o`)
3. **Browsers** — detecta bancos de dados de senhas do Chrome, Edge, Brave e Opera em disco

> Senhas curtas (< 8 chars) são sinalizadas como `MÉDIO` no score de risco.

---

## ⚠️ Aviso Legal

Esta ferramenta é destinada exclusivamente para auditoria de **sistemas próprios ou com autorização explícita**. O uso não autorizado em sistemas de terceiros é ilegal.

---

## 👤 Créditos

Desenvolvido por **Fernando Garcia**  
🔗 [github.com/ferpgshy](https://github.com/ferpgshy)
