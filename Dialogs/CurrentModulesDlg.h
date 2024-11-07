#pragma once
// CurrentModulesDlg 对话框
class CurrentModulesDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CurrentModulesDlg)

public:
	CurrentModulesDlg(DWORD dwPid,CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~CurrentModulesDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG1 };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	virtual BOOL OnInitDialog();
	virtual void PostNcDestroy() override;
	DECLARE_MESSAGE_MAP()
private:
	CListCtrl ProcModulesList;
	DWORD m_dwPid;
};
