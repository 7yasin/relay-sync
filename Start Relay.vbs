Dim objShell, objFSO, projectPath, envPath, command

Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

projectPath = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))
envPath = projectPath & ".env"

If objFSO.FileExists(envPath) Then
    command = "cmd /k ""cd /d """ & projectPath & """ && node index.js"""
Else
    command = "cmd /k ""cd /d """ & projectPath & """ && node setup.js && node index.js"""
End If

' Start Relay in a visible command window.
' To stop Relay, press CTRL + C or close the command window.
objShell.Run command, 1, False