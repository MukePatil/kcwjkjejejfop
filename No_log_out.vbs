' $language = "VBScript"
' $interface = "1.0"

Dim refreshIntervalSeconds
Dim keepaliveCommand

refreshIntervalSeconds = 600  ' every 300 seconds
keepaliveCommand = vbCr       ' send just Enter; use "show clock" & vbCr if needed

Sub KeepAliveAllTabs()
    Dim tabCount, i, tab
    tabCount = crt.GetTabCount()

    For i = 0 To tabCount - 1
        Set tab = crt.GetTab(i + 1)
        If tab.Session.Connected Then
            tab.Screen.Send keepaliveCommand
            crt.Sleep 500  ' 0.5 second between tabs
        End If
    Next
End Sub

' Infinite loop — use Ctrl+Break in SecureCRT to stop
Do
    KeepAliveAllTabs
    crt.Sleep refreshIntervalSeconds * 1000
Loop
