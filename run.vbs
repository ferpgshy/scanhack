Option Explicit

' ─────────────────────────────────────────────────────────────────
'  SecurityAudit — launcher silencioso
'  Executa sem janelas visíveis: só aparece a UAC (obrigatória) e
'  o browser que abre automaticamente com a interface de progresso.
'  Use run.bat se quiser ver a saída no terminal.
' ─────────────────────────────────────────────────────────────────

Dim objFSO, objShell, sDir, sPwsh, sArgs

Set objFSO   = CreateObject("Scripting.FileSystemObject")
Set objShell = CreateObject("Shell.Application")

' Diretório do próprio script VBS
sDir = objFSO.GetParentFolderName(WScript.ScriptFullName)

' Detecta PowerShell 7 (pwsh); fallback para PS 5.1 nativo
sPwsh = "powershell.exe"
If objFSO.FileExists("C:\Program Files\PowerShell\7\pwsh.exe") Then
    sPwsh = "C:\Program Files\PowerShell\7\pwsh.exe"
ElseIf objFSO.FileExists("C:\Program Files\PowerShell\7-preview\pwsh.exe") Then
    sPwsh = "C:\Program Files\PowerShell\7-preview\pwsh.exe"
End If

sArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ _
      & sDir & "\SecurityAudit.ps1"""

' verb "runas" = UAC  |  último param 0 = SW_HIDE (janela oculta)
objShell.ShellExecute sPwsh, sArgs, sDir, "runas", 0
