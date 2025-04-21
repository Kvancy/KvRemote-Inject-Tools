#pragma once
#include"../R3Tools/wr3Tool.h"
#include<memory>
class CKvRemoteInjectToolsDlg : public CDialogEx
{
public:
	CKvRemoteInjectToolsDlg(CWnd* pParent = nullptr);	

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_KVREMOTEINJECTTOOLS_DIALOG };
#endif
protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持

protected:
	HICON m_hIcon;

	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CEdit CEDIT_DllPath;
	CComboBox CCombox_ProcList;
	CButton Check_IsRepairVPM;
	CString KeyDllPath{ _T("dllpath") };
	CString KeyProcName{ _T("procName") };
	CString KeyIsRepairVPM{ _T("isRepairVPM") };
	CString KeyRemoteInject{ _T("RemoteInject") };
	CString KeyApcInject{ _T("ApcInject") };
	CString KeyReflectiveInject{ _T("ReflectiveInject") };
	CButton Radio_Exist;
	CButton Radio_New;
	CButton CButton_Inject;
	CEdit CEDIT_DelayTime;
	static bool WriteToIni(const CString& key, const CString& value, const CString& section = _T("Settings"), const CString& iniFilePath = _T(".\\config.ini"));
	static CString ReadFromIni(const CString& key, const CString& defaultValue = _T(""), const CString& section = _T("Settings"), const CString& iniFilePath = _T(".\\config.ini"));;
	afx_msg void OnBnClicked_Inject();
	afx_msg void OnBnClicked_SelectDll();
	afx_msg void OnCbnDropdownCombo1();
	afx_msg void OnClose();
	afx_msg void ViewCurrentModule();
	BOOL CKvRemoteInjectToolsDlg::transCString2ByteArray(CString cs, BYTE* retByteArray, DWORD* size);
	afx_msg void OnBnClickedRadioNew();
	afx_msg void OnBnClickedRadioExist();
	CButton Radio_RemoteInject;
	CButton Radio_ApcInject;
	CButton Radio_ReflectiveInject;
	CEdit CEDIT_ShellCode;
	afx_msg void OnBnClickedRadio3();
	afx_msg void OnBnClickedRadioApc();
	afx_msg void OnBnClickedRadioReflective();
};
