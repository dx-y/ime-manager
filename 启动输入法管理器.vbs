' 静默启动输入法管理器（无黑色控制台窗口）
' 2026-09-20 修复：改为绝对路径调用 pythonw.exe，避免双击时因 PATH 不含运行时目录而静默失败
Set fso = CreateObject("Scripting.FileSystemObject")
Set ws = CreateObject("Wscript.Shell")
ws.CurrentDirectory = fso.GetParentFolderName(WScript.ScriptFullName)
pyw = "G:\软件安装文件夹\Marvis\MarvisAgent\1.60.2600.614\runtime\python311\pythonw.exe"
If Not fso.FileExists(pyw) Then
    MsgBox "未找到 pythonw.exe：" & pyw & vbCrLf & "请检查 Marvis 运行时路径是否已变更。", vbCritical, "输入法管理器"
    WScript.Quit
End If
ws.Run """" & pyw & """ launcher.py", 0, False
