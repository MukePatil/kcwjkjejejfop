#$language = "VBScript"
#$interface = "1.0"

Sub Main
    Dim logFolder, fso
    logFolder = "C:\Logs"   ' Make sure this folder exists or update as needed

    Set fso = CreateObject("Scripting.FileSystemObject")
    If Not fso.FolderExists(logFolder) Then
        fso.CreateFolder(logFolder)
    End If

    Dim i, tab, hostname, logFilename
    For i = 1 To crt.GetTabCount
        Set tab = crt.GetTab(i)

        If tab.Session.Connected Then
            tab.Activate

            On Error Resume Next
            hostname = tab.Session.Config.GetOption("Hostname")
            If hostname = "" Then
                hostname = "Tab_" & i
            End If
            On Error GoTo 0

            ' Clean invalid characters for Windows filenames
            hostname = Replace(hostname, "\", "_")
            hostname = Replace(hostname, "/", "_")
            hostname = Replace(hostname, ":", "_")
            hostname = Replace(hostname, "*", "_")
            hostname = Replace(hostname, "?", "_")
            hostname = Replace(hostname, """", "_")
            hostname = Replace(hostname, "<", "_")
            hostname = Replace(hostname, ">", "_")
            hostname = Replace(hostname, "|", "_")

            logFilename = logFolder & "\" & hostname & ".log"

            tab.Session.LogFileName = logFilename
            tab.Session.Log True
        End If
    Next
End Sub