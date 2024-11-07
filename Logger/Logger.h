#pragma once
#include <iostream>
#include <fstream>
#include <ctime>
#include <string>
#include <vector>
class Logger {
private:
    static std::string logMessages;

public:
    Logger() {}

    // string����ƴ����־��Ϣ����ӡ
    static void log();
    //��Ӹ�ʽ������־�����ʽ
    static void log(const char* message);
    // �ṩһ���������������־��Ϣ���Ա��ڵ��� log ֮ǰ����ƴ��
    static void addMessage(const char* additionalMessage);
    // ��ӿ�ݴ�ӡ�쳣��Ϣ�������쳣�뼴��
    static void logError(const char* callingFunction, int errorCode, int lineNumber = -1);
};
