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

    // string类型拼接日志信息并打印
    static void log();
    //添加格式化的日志输出方式
    static void log(const char* message);
    // 提供一个方法用于添加日志信息，以便在调用 log 之前进行拼接
    static void addMessage(const char* additionalMessage);
    // 添加快捷打印异常信息，传入异常码即可
    static void logError(const char* callingFunction, int errorCode, int lineNumber = -1);
};
