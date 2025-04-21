#include <pch.h>
#include <TlHelp32.h>
#include <vector>
#include "../App/KvRemote-Inject-Tools.h"
#include "CurrentModulesDlg.h"


IMPLEMENT_DYNAMIC(CurrentModulesDlg, CDialogEx)

CurrentModulesDlg::CurrentModulesDlg(DWORD dwPid,CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG1, pParent),m_dwPid(dwPid)
{
}

CurrentModulesDlg::~CurrentModulesDlg()
{
}

void CurrentModulesDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_ProcModlist, ProcModulesList);
}

BOOL CurrentModulesDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();
	// 列表属性
	ProcModulesList.SetExtendedStyle(ProcModulesList.GetExtendedStyle());
	ProcModulesList.ModifyStyle(0, LVS_REPORT);
	//模块名，模块基址，模块大小
	ProcModulesList.InsertColumn(0, "模块名", LVCFMT_LEFT, 300, 0);    //设置列
	ProcModulesList.InsertColumn(1, "模块基址", LVCFMT_LEFT, 300, 0);    //设置列
	ProcModulesList.InsertColumn(2, "模块大小", LVCFMT_LEFT, 300, 0);    //设置列
	ProcModulesList.SetColumnWidth(0, 100);
	ProcModulesList.SetColumnWidth(1, 130);
	ProcModulesList.SetColumnWidth(2, 100);
	DWORD index = 0;
	CHAR tmp[20] = { 0 };
	DWORD moduleNum = 0;
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_dwPid);
	if (hModuleSnap != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 me32;
		me32.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hModuleSnap, &me32)) {
			do {
				index = ProcModulesList.InsertItem(0, me32.szModule);
				sprintf(tmp, "%p", me32.modBaseAddr);
				ProcModulesList.SetItemText(index, 1, tmp);
				sprintf(tmp, "0x%02x", me32.modBaseSize);
				ProcModulesList.SetItemText(index, 2, tmp);
				moduleNum ++;
			} while (Module32Next(hModuleSnap, &me32));
		}
		CloseHandle(hModuleSnap);
	}
	// 刷新列表视图以显示更新
	sprintf(tmp, "当前模块%d个", moduleNum);
	SetWindowText(tmp);
	ProcModulesList.Invalidate();
	return 0;
}
//保证每次关闭窗口时析构函数，从而刷新界面
void CurrentModulesDlg::PostNcDestroy()
{
	delete this;
}

BEGIN_MESSAGE_MAP(CurrentModulesDlg, CDialogEx)
END_MESSAGE_MAP()


// CurrentModulesDlg 消息处理程序
