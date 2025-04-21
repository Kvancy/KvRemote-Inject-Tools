#include <pch.h>
#include <framework.h>
#include "../App/KvRemote-Inject-Tools.h"
#include "KvRemote-Inject-ToolsDlg.h"
#include "afxdialogex.h"
#include "CurrentModulesDlg.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    

protected:
	DECLARE_MESSAGE_MAP()
public:
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


CKvRemoteInjectToolsDlg::CKvRemoteInjectToolsDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_KVREMOTEINJECTTOOLS_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CKvRemoteInjectToolsDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, CEDIT_DllPath);
	DDX_Control(pDX, IDC_COMBO1, CCombox_ProcList);
	DDX_Control(pDX, IDC_CHECK1, Check_IsRepairVPM);
	DDX_Control(pDX, IDC_RADIO1, Radio_Exist);
	DDX_Control(pDX, IDC_RADIO2, Radio_New);
	DDX_Control(pDX, IDC_BUTTON2, CButton_Inject);
	DDX_Control(pDX, IDC_EDIT2, CEDIT_DelayTime);
	DDX_Control(pDX, IDC_RADIO3, Radio_RemoteInject);
	DDX_Control(pDX, IDC_RADIO4, Radio_ApcInject);
	DDX_Control(pDX, IDC_RADIO5, Radio_ReflectiveInject);
	DDX_Control(pDX, IDC_EDIT3, CEDIT_ShellCode);
}

BEGIN_MESSAGE_MAP(CKvRemoteInjectToolsDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON2, &CKvRemoteInjectToolsDlg::OnBnClicked_Inject)
	ON_BN_CLICKED(IDC_BUTTON1, &CKvRemoteInjectToolsDlg::OnBnClicked_SelectDll)
	ON_CBN_DROPDOWN(IDC_COMBO1, &CKvRemoteInjectToolsDlg::OnCbnDropdownCombo1)
	ON_WM_CANCELMODE()
	ON_WM_CLOSE()
	ON_BN_CLICKED(IDC_BUTTON3, &CKvRemoteInjectToolsDlg::ViewCurrentModule)
	ON_BN_CLICKED(IDC_RADIO2, &CKvRemoteInjectToolsDlg::OnBnClickedRadioNew)
	ON_BN_CLICKED(IDC_RADIO1, &CKvRemoteInjectToolsDlg::OnBnClickedRadioExist)
	ON_BN_CLICKED(IDC_RADIO3, &CKvRemoteInjectToolsDlg::OnBnClickedRadio3)
	ON_BN_CLICKED(IDC_RADIO4, &CKvRemoteInjectToolsDlg::OnBnClickedRadioApc)
	ON_BN_CLICKED(IDC_RADIO5, &CKvRemoteInjectToolsDlg::OnBnClickedRadioReflective)
END_MESSAGE_MAP()


BOOL CKvRemoteInjectToolsDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}
	//初始化配置，跟上次关闭保持一致状态
	CEDIT_ShellCode.SetWindowTextA("0x90,0x90");
	CEDIT_DllPath.SetWindowTextA(ReadFromIni(KeyDllPath));
	CCombox_ProcList.SetWindowTextA(ReadFromIni(KeyProcName));
	Check_IsRepairVPM.SetCheck(ReadFromIni(KeyIsRepairVPM) == _T("true"));
	Radio_RemoteInject.SetCheck(ReadFromIni(KeyRemoteInject) == _T("true"));
	Radio_ApcInject.SetCheck(ReadFromIni(KeyApcInject) == _T("true"));
	Radio_ReflectiveInject.SetCheck(ReadFromIni(KeyReflectiveInject) == _T("true"));
	Radio_Exist.SetCheck(true);
	SetIcon(m_hIcon, TRUE);			
	SetIcon(m_hIcon, FALSE);		


	return TRUE;  
}

void CKvRemoteInjectToolsDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

void CKvRemoteInjectToolsDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); 

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

HCURSOR CKvRemoteInjectToolsDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

bool CKvRemoteInjectToolsDlg::WriteToIni(const CString& key, const CString& value, const CString& section, const CString& iniFilePath)
{
	BOOL result = WritePrivateProfileString(section, key, value, iniFilePath);
	return result == TRUE;
}

CString CKvRemoteInjectToolsDlg::ReadFromIni(const CString& key, const CString& defaultValue, const CString& section, const CString& iniFilePath)
{
	TCHAR buffer[MAX_PATH];
	DWORD result = GetPrivateProfileString(section, key, defaultValue, buffer, MAX_PATH, iniFilePath);
	return CString(buffer);
}

void CKvRemoteInjectToolsDlg::OnBnClicked_Inject()
{
	UpdateData(TRUE);
	CString dllBuffer;
	CEDIT_DllPath.GetWindowTextA(dllBuffer);
	CString shellCodeBuffer;
	CEDIT_ShellCode.GetWindowTextA(shellCodeBuffer);
	HANDLE hProcess = 0;
	int sleepTime = 2000;
	if (dllBuffer.IsEmpty()) {
		MessageBox("请选择dll文件");
		return;
	}
	if (Radio_New.GetCheck() == BST_CHECKED)
	{
		CString exePath;
		CCombox_ProcList.GetWindowTextA(exePath);
		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		ZeroMemory(&pi, sizeof(pi));
		ZeroMemory(&si, sizeof(si));

		si.cb = sizeof(si);

		if (!CreateProcess(exePath.GetBuffer(),NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
		{
			int d = GetLastError();
			MessageBox("启动进程失败,请检查进程路径和所有权限");
			return;
		}
		CString tmp;
		CEDIT_DelayTime.GetWindowTextA(tmp);
		sleepTime = StrToInt(tmp.GetBuffer());
		hProcess = pi.hProcess;
	}
	int dllPathLen = dllBuffer.GetLength();
	char* dllPath = dllBuffer.GetBuffer();
	dllPath[dllPathLen] = 0;

	wr3Tool::EnableDebugPrivilege();

	//如果是注入已存在的进程，查找进程句柄
	if (!hProcess)
	{
		//格式化字符串获取到pid
		CString selectedText;
		CCombox_ProcList.GetWindowTextA(selectedText);
		int pos = selectedText.Find(_T('-'));
		int pid = 0;
		if (pos != -1)
		{
			selectedText = selectedText.Mid(pos + 1);
			pid = _ttoi(selectedText);
		}
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (!hProcess)
		{
			MessageBox("进程句柄打开失败，请确认进程存在或者权限足够");
			return;
		}
	}
	Sleep(sleepTime);

	//选中修复VirtualProtect
	if (Check_IsRepairVPM.GetCheck())
	{
		if (!wr3Tool::RepairVirtualProtect(hProcess))
		{
			MessageBox("修复hook失败，调试程序获取更多信息");
			return;
		}
	}
	if (Radio_RemoteInject.GetCheck() == BST_CHECKED)
	{
		if (!wr3Tool::RemoteThreadInjectDll(hProcess, dllPath))
		{
			MessageBox("注入失败，调试程序获取更多信息");
			return;
		}
		else
		{
			MessageBox("注入成功!");
		}
	}
	else if (Radio_ApcInject.GetCheck() == BST_CHECKED)
	{
		if (!wr3Tool::ApcInjectDll(hProcess, dllPath))
		{
			MessageBox("注入失败，调试程序获取更多信息");
			return;
		}
		else
		{
			MessageBox("注入成功!");
		}
	}
	else if (Radio_ReflectiveInject.GetCheck() == BST_CHECKED)
	{
		if(shellCodeBuffer.IsEmpty() == TRUE) {
			MessageBox("请输入需要注入的ShellCode");
			return;
		}
		BYTE* shellCode = new BYTE[1024];
		DWORD size = 0;
		if (!transCString2ByteArray(shellCodeBuffer, shellCode,&size)) {
			MessageBox("ShellCode格式错误");
			return;
		}
		if (!wr3Tool::ReflectiveInjectDll(hProcess, shellCode,size))
		{
			MessageBox("注入失败，调试程序获取更多信息");
			return;
		}
		else
		{
			delete shellCode;
			MessageBox("注入成功!");
		}
	}
	return;
}

void CKvRemoteInjectToolsDlg::OnBnClicked_SelectDll()
{
	CString filter = _T("Dll Files (*.dll)|*.dll|All Files (*.*)|*.*||");
	CFileDialog dlg(true, _T(""), _T(""), OFN_FILEMUSTEXIST | OFN_HIDEREADONLY, filter);
	if (dlg.DoModal() == IDCANCEL) {
		return;
	}
	CString filePath = dlg.GetPathName();
	if (filePath.Right(4).CompareNoCase(_T(".dll")) != 0)
	{
		AfxMessageBox(_T("请选择.dll文件"));
		return;
	}
	CEDIT_DllPath.SetWindowTextA(filePath);
	UpdateData(FALSE);
}

void CKvRemoteInjectToolsDlg::OnCbnDropdownCombo1()
{
	CCombox_ProcList.ResetContent();
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnapshot, &pe32))
		{
			do
			{
				CString item;
				item.Format(_T("%s - %d"), pe32.szExeFile, pe32.th32ProcessID);
				CCombox_ProcList.AddString(item);
			} while (Process32Next(hSnapshot, &pe32));
		}
		CloseHandle(hSnapshot);
	}
}

void CKvRemoteInjectToolsDlg::OnClose()
{
	CString value;
	CEDIT_DllPath.GetWindowTextA(value);
	WriteToIni(KeyDllPath, value);

	CCombox_ProcList.GetWindowTextA(value);
	WriteToIni(KeyProcName, value);

	if (Check_IsRepairVPM.GetCheck())
		value = _T("true");
	else
		value = _T("false");

	WriteToIni(KeyIsRepairVPM, value);
	WriteToIni(KeyRemoteInject, Radio_RemoteInject.GetCheck() == true ? _T("true"):_T("false"));
	WriteToIni(KeyApcInject, Radio_ApcInject.GetCheck() == true ? _T("true"):_T("false"));
	WriteToIni(KeyReflectiveInject, Radio_ReflectiveInject.GetCheck() == true ? _T("true"):_T("false"));
	CDialogEx::OnClose();
}

void CKvRemoteInjectToolsDlg::ViewCurrentModule()
{
	CString selectedText;
	CCombox_ProcList.GetWindowTextA(selectedText);
	int pos = selectedText.Find(_T('-'));
	int pid = 0;
	if (pos != -1)
	{
		selectedText = selectedText.Mid(pos + 1);
		pid = _ttoi(selectedText);
		CurrentModulesDlg* dlg = new CurrentModulesDlg(pid);
		dlg->DoModal();
	}
	else
	{
		MessageBox("没有找到进程PID");
		return;
	}
	
}

BOOL CKvRemoteInjectToolsDlg::transCString2ByteArray(CString cs, BYTE* retByteArray, DWORD* size) {
	CStringArray arrParts;
	CByteArray byteArray;

	int pos = 0;
	CString token;
	while ((token = cs.Tokenize(",", pos)) != "") {
		arrParts.Add(token);
	}

	for (int i = 0; i < arrParts.GetCount(); i++) {
		CString part = arrParts[i];
		part.Trim();

		BYTE byteVal;
		// 使用%02hhX匹配BYTE类型
		if (_stscanf_s(part, _T("0x%02hhX"), &byteVal) == 1) {
			byteArray.Add(byteVal);
		}
		else {
			AfxMessageBox(_T("ShellCode格式错误: ") + part);
			return FALSE;
		}
	}

	*size = byteArray.GetCount();

	if (retByteArray == NULL || *size == 0) {
		return FALSE;
	}

	memcpy(retByteArray, byteArray.GetData(), *size);

	return TRUE;
}


void CKvRemoteInjectToolsDlg::OnBnClickedRadioNew()
{
	CCombox_ProcList.EnableWindow(false);
	CEDIT_DelayTime.EnableWindow(true);
	CEDIT_DelayTime.SetWindowTextA("2000");
	CString filter = _T("EXE Files (*.exe)|*.exe|All Files (*.*)|*.*||");
	CFileDialog dlg(true, _T(""), _T(""), OFN_FILEMUSTEXIST | OFN_HIDEREADONLY, filter);
	if (dlg.DoModal() == IDCANCEL) {
		return;
	}
	CString filePath = dlg.GetPathName();
	if (filePath.Right(4).CompareNoCase(_T(".exe")) != 0)
	{
		AfxMessageBox(_T("请选择要启动的进程"));
		return;
	}
	CCombox_ProcList.SetWindowTextA(filePath);
	CButton_Inject.SetWindowTextA("启动并注入");
	UpdateData(FALSE);
}



void CKvRemoteInjectToolsDlg::OnBnClickedRadioExist()
{
	CEDIT_DelayTime.EnableWindow(false);
	CCombox_ProcList.EnableWindow(true);
}

void CKvRemoteInjectToolsDlg::OnBnClickedRadio3()
{
	CEDIT_DelayTime.EnableWindow(false);
	CCombox_ProcList.EnableWindow(true);
	CEDIT_ShellCode.EnableWindow(false);
}

void CKvRemoteInjectToolsDlg::OnBnClickedRadioApc()
{
	CEDIT_DelayTime.EnableWindow(false);
	CCombox_ProcList.EnableWindow(true);
	CEDIT_ShellCode.EnableWindow(false);
}

void CKvRemoteInjectToolsDlg::OnBnClickedRadioReflective()
{
	CEDIT_DelayTime.EnableWindow(false);
	CCombox_ProcList.EnableWindow(true);
	CEDIT_ShellCode.EnableWindow(true);

}
