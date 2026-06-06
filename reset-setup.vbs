Dim objShell, projectPath, command

Set objShell = CreateObject("WScript.Shell")

projectPath = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))

command = "cmd /k ""cd /d """ & projectPath & """ && node setup.js --reset"""

objShell.Run command, 1, False