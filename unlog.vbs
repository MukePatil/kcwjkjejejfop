' $language = "VBScript"
' $interface = "1.0"

Sub StopLogOnAllSessions()
    Dim i, tab
    For i = 1 To crt.GetTabCount()   ' SecureCRT tabs are 1-based
        Set tab = crt.GetTab(i)
        If tab.Session.Connected Then
            On Error Resume Next
            ' Try to stop logging regardless of state
            tab.Session.Log False
            On Error GoTo 0
        End If
    Next
End Sub

StopLogOnAllSessions
