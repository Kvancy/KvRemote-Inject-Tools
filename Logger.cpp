#include"pch.h"
#include"Logger.h"

std::string Logger::logMessages;

void Logger::log() {
    if (!logMessages.empty()) {
        std::ofstream logFile("log.txt", std::ios_base::app);
        if (logFile.is_open()) {
            time_t now = time(nullptr);
            char* dt = ctime(&now);
            logFile << dt << logMessages << std::endl;
            logFile.close();

            // 清空日志信息存储容器
            logMessages.clear();
        }
        else {
            MessageBox(NULL, TEXT("无法打开日志文件"), NULL, NULL);
        }
    }
}

void Logger::log(const char* message) {
    if (message != NULL) {
        std::ofstream logFile("log.txt", std::ios_base::app);
        if (logFile.is_open()) {
            time_t now = time(nullptr);
            char* dt = ctime(&now);
            logFile << dt << message << std::endl;
            logFile.close();

            logMessages.clear();
        }
        else {
            MessageBox(NULL, TEXT("无法打开日志文件"), NULL, NULL);
        }
    }
}

void Logger::addMessage(const char* additionalMessage) {
    if (additionalMessage != nullptr) {
        logMessages  += std::string(additionalMessage);
    }
}

void Logger::logError(const char* callingFunction,int errorCode, int lineNumber) {
    std::ofstream logFile("log.txt", std::ios_base::app);
    if (logFile.is_open()) {
        time_t now = time(nullptr);
        char* dt = ctime(&now);
        if (lineNumber != -1) {
            logFile << dt << callingFunction << " at line " << lineNumber << " error:" << errorCode << std::endl;
        }
        else {
            logFile << dt << callingFunction << " error:" << errorCode << std::endl;
        }
        logFile.close();

        logMessages.clear();
    }
    else {
        MessageBox(NULL, TEXT("无法打开日志文件"), NULL, NULL);
    }
}