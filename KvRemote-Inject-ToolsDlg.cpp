#include "pch.h"
#include "framework.h"
#include "KvRemote-Inject-Tools.h"
#include "KvRemote-Inject-ToolsDlg.h"
#include "afxdialogex.h"

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
	CEDIT_DllPath.SetWindowTextA(ReadFromIni(KeyDllPath));
	CCombox_ProcList.SetWindowTextA(ReadFromIni(KeyProcName));
	Check_IsRepairVPM.SetCheck(ReadFromIni(KeyIsRepairVPM) == _T("true"));

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
	if (dllBuffer.IsEmpty()) {
		MessageBox("请选择dll文件");
		return;
	}
	int dllPathLen = dllBuffer.GetLength();
	char* dllPath = dllBuffer.GetBuffer();
	dllPath[dllPathLen] = 0;
	CString strMsg;
	HANDLE hToken;
	if (FALSE == OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
		MessageBox("打开进程令牌失败");
		return;
	}

	LUID luid;
	if (FALSE == LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		MessageBox("查询进程特权信息失败");
		return;
	}

	TOKEN_PRIVILEGES tkp;
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (FALSE == AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
		MessageBox("令牌权限提升失败");
		return;
	}

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
	//获取进程句柄
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess)
	{
		MessageBox("进程句柄打开失败，请确认进程存在或者权限足够");
		return;
	}

	//选中修复VirtualProtect
	if (Check_IsRepairVPM.GetCheck())
	{
		if (!wr3Tool::RepairVirtualProtect(hProcess))
		{
			MessageBox("修复hook失败，调试程序获取更多信息");
			return;
		}
	}
	
	if (!wr3Tool::InjectDll(hProcess, dllPath))
	{
		MessageBox("注入失败，调试程序获取更多信息");
		return;
	}
	else
	{
		MessageBox("注入成功!");
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

	CDialogEx::OnClose();
}
