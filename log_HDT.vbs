#$Language="VBScript"
#$Interface="1.0"

Sub Main()
    Dim logFolder, fso
    logFolder = "C:\Logs"   ' Make sure this folder exists or update as needed

    Set fso = CreateObject("Scripting.FileSystemObject")
    If Not fso.FolderExists(logFolder) Then
        fso.CreateFolder(logFolder)
    End If

    Dim i, tab, hostname, logFilename, ts
    ts = TimeStamp() ' Create a timestamp once per run (move inside loop if you want per-tab timing)

    For i = 1 To crt.GetTabCount()
        Set tab = crt.GetTab(i)

        If tab.Session.Connected Then
            tab.Activate

            On Error Resume Next
            hostname = tab.Session.Config.GetOption("Hostname")
            On Error GoTo 0

            If Trim(hostname) = "" Then
                hostname = "Tab_" & i
            End If

            ' Clean invalid characters for Windows filenames
            hostname = SanitizeForFilename(hostname)

            ' Build: C:\Logs\<hostname>_YYYY-MM-DD_HH-MM.log
            logFilename = fso.BuildPath(logFolder, hostname & "_" & ts & ".log")

            tab.Session.LogFileName = logFilename
            tab.Session.Log(True)
        End If
    Next
End Sub

Function TimeStamp()
    Dim d
    d = Now
    ' Returns YYYY-MM-DD_HH-MM  (safe for filenames)
    TimeStamp = Year(d) & "-" & _
                Right("0" & Month(d), 2) & "-" & _
                Right("0" & Day(d), 2) & "_" & _
                Right("0" & Hour(d), 2) & "-" & _
                Right("0" & Minute(d), 2)
End Function

Function SanitizeForFilename(name)
    Dim s
    s = name
    s = Replace(s, "\", "_")
    s = Replace(s, "/", "_")
    s = Replace(s, ":", "_")
    s = Replace(s, "*", "_")
    s = Replace(s, "?", "_")
    s = Replace(s, """", "_")
    s = Replace(s, "<", "_")
    s = Replace(s, ">", "_")
    s = Replace(s, "|", "_")
    SanitizeForFilename = s
End Function
