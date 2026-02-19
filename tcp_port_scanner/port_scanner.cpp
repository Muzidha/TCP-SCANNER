/*
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║           TCP PORT SCANNER - Advanced Network Tool              ║
 * ║         Written in C++ | Windows (Winsock2) Compatible          ║
 * ╚══════════════════════════════════════════════════════════════════╝
 *
 * Features:
 *   - Multi-threaded scanning (up to 500 threads)
 *   - Service/banner detection
 *   - Custom port ranges & individual ports
 *   - Response time measurement
 *   - Color-coded output
 *   - Export results to file
 *
 * Compile:
 *   g++ -o port_scanner port_scanner.cpp -lws2_32 -lpthread -std=c++17 -O2
 *
 * Usage:
 *   port_scanner.exe <target> [options]
 *   port_scanner.exe 192.168.1.1 -p 1-1024
 *   port_scanner.exe example.com -p 80,443,8080 -t 200 -o result.txt
 */

/* winsock2.h MUST be included before windows.h */
#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// ─────────────────────────────────────────────
//  ANSI Color Codes (Windows Console)
// ─────────────────────────────────────────────
namespace Color {
const std::string RESET = "\033[0m";
const std::string BOLD = "\033[1m";
const std::string RED = "\033[31m";
const std::string GREEN = "\033[32m";
const std::string YELLOW = "\033[33m";
const std::string BLUE = "\033[34m";
const std::string MAGENTA = "\033[35m";
const std::string CYAN = "\033[36m";
const std::string WHITE = "\033[37m";
const std::string BRED = "\033[1;31m";
const std::string BGREEN = "\033[1;32m";
const std::string BYELLOW = "\033[1;33m";
const std::string BCYAN = "\033[1;36m";
const std::string BWHITE = "\033[1;37m";
} // namespace Color

// ─────────────────────────────────────────────
//  Well-Known Port Services
// ─────────────────────────────────────────────
const std::map<int, std::string> SERVICES = {
    {21, "FTP"},
    {22, "SSH"},
    {23, "Telnet"},
    {25, "SMTP"},
    {53, "DNS"},
    {67, "DHCP"},
    {68, "DHCP"},
    {69, "TFTP"},
    {80, "HTTP"},
    {110, "POP3"},
    {111, "RPC"},
    {119, "NNTP"},
    {123, "NTP"},
    {135, "MSRPC"},
    {137, "NetBIOS"},
    {138, "NetBIOS"},
    {139, "NetBIOS-SSN"},
    {143, "IMAP"},
    {161, "SNMP"},
    {179, "BGP"},
    {194, "IRC"},
    {389, "LDAP"},
    {443, "HTTPS"},
    {445, "SMB"},
    {465, "SMTPS"},
    {514, "Syslog"},
    {515, "LPD"},
    {587, "SMTP-TLS"},
    {636, "LDAPS"},
    {993, "IMAPS"},
    {995, "POP3S"},
    {1080, "SOCKS"},
    {1194, "OpenVPN"},
    {1433, "MSSQL"},
    {1521, "Oracle-DB"},
    {1723, "PPTP"},
    {2049, "NFS"},
    {2375, "Docker"},
    {2376, "Docker-TLS"},
    {3000, "HTTP-Dev"},
    {3306, "MySQL"},
    {3389, "RDP"},
    {4444, "Metasploit"},
    {5000, "HTTP-Flask"},
    {5432, "PostgreSQL"},
    {5900, "VNC"},
    {5985, "WinRM-HTTP"},
    {5986, "WinRM-HTTPS"},
    {6379, "Redis"},
    {6443, "Kubernetes"},
    {7001, "WebLogic"},
    {8000, "HTTP-Alt"},
    {8080, "HTTP-Proxy"},
    {8443, "HTTPS-Alt"},
    {8888, "Jupyter"},
    {9000, "PHP-FPM"},
    {9090, "Prometheus"},
    {9200, "Elasticsearch"},
    {9300, "Elasticsearch"},
    {10250, "Kubelet"},
    {27017, "MongoDB"},
    {27018, "MongoDB"},
    {50000, "SAP"},
};

// ─────────────────────────────────────────────
//  Scan Result Structure
// ─────────────────────────────────────────────
struct ScanResult {
  int port;
  bool open;
  long responseTimeMs;
  std::string service;
  std::string banner;
};

// ─────────────────────────────────────────────
//  Scanner Configuration
// ─────────────────────────────────────────────
struct ScanConfig {
  std::string target;
  std::string resolvedIP;
  std::vector<int> ports;
  int timeout = 2000; // ms
  int threads = 100;
  bool grabBanner = true;
  bool verboseMode = false;
  std::string outputFile;
};

// ─────────────────────────────────────────────
//  Global State
// ─────────────────────────────────────────────
std::mutex g_printMtx;
std::mutex g_resultMtx;
std::vector<ScanResult> g_results;
std::atomic<int> g_scanned(0);
std::atomic<int> g_openCount(0);
int g_totalPorts = 0;

// ─────────────────────────────────────────────
//  Enable ANSI in Windows Console
// ─────────────────────────────────────────────
void enableAnsiColors() {
  SetConsoleOutputCP(CP_UTF8);
  HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
  if (hOut != INVALID_HANDLE_VALUE) {
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
  }
}

// ─────────────────────────────────────────────
//  Banner / Header
// ─────────────────────────────────────────────
void printBanner() {
  std::cout << Color::BCYAN;
  std::cout << "\n";
  std::cout
      << "  ######  ######  ######     #####   ####  ##### ####  ##  ##\n";
  std::cout
      << "    ##   ##      ##   ##    ##      ##    ##    ##  ## ##  ##\n";
  std::cout
      << "    ##   ##      ######      ####   ##    ####  #####  ######\n";
  std::cout
      << "    ##   ##      ##             ##  ##    ##    ## ##  ##  ##\n";
  std::cout
      << "    ##    ######  ##        #####    ####  ##### ##  ## ##  ##\n";
  std::cout << Color::RESET;
  std::cout << Color::BYELLOW;
  std::cout << "\n          [ TCP Port Scanner v1.0 | C++ Edition | GCC 15 ]\n";
  std::cout << Color::RESET;
  std::cout
      << Color::WHITE
      << "  ================================================================\n"
      << Color::RESET;
  std::cout << "\n";
}

// ─────────────────────────────────────────────
//  Usage / Help
// ─────────────────────────────────────────────
void printHelp(const char *prog) {
  std::cout << Color::BWHITE << "\nUSAGE:\n" << Color::RESET;
  std::cout << "  " << prog << " <target> [options]\n\n";

  std::cout << Color::BWHITE << "ARGUMENTS:\n" << Color::RESET;
  std::cout << "  <target>            Hostname or IP address to scan\n\n";

  std::cout << Color::BWHITE << "OPTIONS:\n" << Color::RESET;
  std::cout << "  -p <ports>          Port specification (default: 1-1024)\n";
  std::cout << "                        Range:    -p 1-65535\n";
  std::cout << "                        List:     -p 80,443,8080\n";
  std::cout << "                        Mixed:    -p 1-100,443,8000-9000\n";
  std::cout
      << "  -t <threads>        Number of threads (default: 100, max: 500)\n";
  std::cout
      << "  -T <timeout>        Timeout in milliseconds (default: 2000)\n";
  std::cout << "  -o <file>           Save results to output file\n";
  std::cout << "  -v                  Verbose mode (show closed ports too)\n";
  std::cout << "  -nb                 No banner grabbing\n";
  std::cout << "  -h                  Show this help\n\n";

  std::cout << Color::BWHITE << "EXAMPLES:\n" << Color::RESET;
  std::cout << "  " << prog << " 192.168.1.1\n";
  std::cout << "  " << prog << " 192.168.1.1 -p 1-1024\n";
  std::cout << "  " << prog << " scanme.nmap.org -p 80,443,22 -t 50\n";
  std::cout << "  " << prog
            << " 10.0.0.1 -p 1-65535 -t 500 -T 1000 -o results.txt\n\n";
}

// ─────────────────────────────────────────────
//  Progress Bar
// ─────────────────────────────────────────────
void printProgress() {
  int scanned = g_scanned.load();
  int total = g_totalPorts;
  int open = g_openCount.load();

  if (total == 0)
    return;

  float pct = (float)scanned / total;
  int fill = (int)(pct * 40);

  std::lock_guard<std::mutex> lock(g_printMtx);
  std::cout << "\r  " << Color::CYAN << "[";
  for (int i = 0; i < 40; i++)
    std::cout << (i < fill ? "█" : "░");
  std::cout << "] " << Color::BYELLOW << std::setw(3) << (int)(pct * 100) << "%"
            << Color::RESET << " | Scanned: " << Color::WHITE << scanned << "/"
            << total << Color::RESET << " | Open: " << Color::BGREEN << open
            << Color::RESET << "   " << std::flush;
}

// ─────────────────────────────────────────────
//  Resolve Hostname to IP
// ─────────────────────────────────────────────
std::string resolveHost(const std::string &host) {
  struct addrinfo hints{}, *res = nullptr;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0)
    return "";

  char ipStr[INET_ADDRSTRLEN];
  struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
  inet_ntop(AF_INET, &addr->sin_addr, ipStr, sizeof(ipStr));
  freeaddrinfo(res);
  return std::string(ipStr);
}

// ─────────────────────────────────────────────
//  Grab Banner from Open Port
// ─────────────────────────────────────────────
std::string grabBanner(const std::string &ip, int port, int timeoutMs) {
  SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET)
    return "";

  DWORD timeout = (DWORD)timeoutMs;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout,
             sizeof(timeout));
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout,
             sizeof(timeout));

  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons((u_short)port);
  inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    closesocket(sock);
    return "";
  }

  // Send probe for HTTP
  if (port == 80 || port == 8080 || port == 8000 || port == 8888) {
    const char *req = "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    send(sock, req, (int)strlen(req), 0);
  }

  char buf[512] = {};
  int received = recv(sock, buf, sizeof(buf) - 1, 0);
  closesocket(sock);

  if (received > 0) {
    std::string banner(buf, received);
    // Clean up: replace non-printable chars
    std::string clean;
    for (char c : banner) {
      if (c == '\n' || c == '\r') {
        clean += ' ';
      } else if (c >= 32 && c < 127) {
        clean += c;
      }
    }
    // Trim
    size_t end = clean.find_last_not_of(' ');
    if (end != std::string::npos)
      clean = clean.substr(0, end + 1);
    if (clean.size() > 80)
      clean = clean.substr(0, 80) + "...";
    return clean;
  }
  return "";
}

// ─────────────────────────────────────────────
//  Scan a Single Port
// ─────────────────────────────────────────────
ScanResult scanPort(const std::string &ip, int port, const ScanConfig &cfg) {
  ScanResult result;
  result.port = port;
  result.open = false;
  result.banner = "";

  // Service name lookup
  auto it = SERVICES.find(port);
  result.service = (it != SERVICES.end()) ? it->second : "unknown";

  SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET) {
    result.responseTimeMs = -1;
    return result;
  }

  // Set non-blocking
  u_long mode = 1;
  ioctlsocket(sock, FIONBIO, &mode);

  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons((u_short)port);
  inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

  auto startTime = std::chrono::steady_clock::now();
  connect(sock, (struct sockaddr *)&addr, sizeof(addr));

  // Use select() to wait
  fd_set wset;
  FD_ZERO(&wset);
  FD_SET(sock, &wset);

  struct timeval tv;
  tv.tv_sec = cfg.timeout / 1000;
  tv.tv_usec = (cfg.timeout % 1000) * 1000;

  int sel = select(0, nullptr, &wset, nullptr, &tv);

  auto endTime = std::chrono::steady_clock::now();
  result.responseTimeMs =
      std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime)
          .count();

  if (sel > 0 && FD_ISSET(sock, &wset)) {
    // Verify connection actually succeeded
    int error = 0;
    int errLen = sizeof(error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&error, &errLen);
    if (error == 0) {
      result.open = true;
      g_openCount++;
    }
  }

  closesocket(sock);

  // Grab banner if port is open
  if (result.open && cfg.grabBanner) {
    result.banner = grabBanner(ip, port, cfg.timeout / 2);
  }

  return result;
}

// ─────────────────────────────────────────────
//  Thread Worker
// ─────────────────────────────────────────────
class ThreadPool {
public:
  ThreadPool(size_t numThreads) : stop_(false) {
    for (size_t i = 0; i < numThreads; i++) {
      workers_.emplace_back([this] {
        while (true) {
          std::function<void()> task;
          {
            std::unique_lock<std::mutex> lock(mtx_);
            cond_.wait(lock, [this] { return stop_ || !tasks_.empty(); });
            if (stop_ && tasks_.empty())
              return;
            task = std::move(tasks_.front());
            tasks_.pop();
          }
          task();
        }
      });
    }
  }

  template <class F> void enqueue(F &&f) {
    {
      std::lock_guard<std::mutex> lock(mtx_);
      tasks_.emplace(std::forward<F>(f));
    }
    cond_.notify_one();
  }

  ~ThreadPool() {
    {
      std::lock_guard<std::mutex> lock(mtx_);
      stop_ = true;
    }
    cond_.notify_all();
    for (auto &w : workers_)
      w.join();
  }

private:
  std::vector<std::thread> workers_;
  std::queue<std::function<void()>> tasks_;
  std::mutex mtx_;
  std::condition_variable cond_;
  bool stop_;
};

// ─────────────────────────────────────────────
//  Parse Port Specification
// ─────────────────────────────────────────────
std::vector<int> parsePorts(const std::string &spec) {
  std::set<int> portSet;
  std::stringstream ss(spec);
  std::string token;

  while (std::getline(ss, token, ',')) {
    // Trim
    token.erase(0, token.find_first_not_of(" \t"));
    token.erase(token.find_last_not_of(" \t") + 1);

    size_t dash = token.find('-');
    if (dash != std::string::npos) {
      int lo = std::stoi(token.substr(0, dash));
      int hi = std::stoi(token.substr(dash + 1));
      if (lo > hi)
        std::swap(lo, hi);
      lo = std::max(1, lo);
      hi = std::min(65535, hi);
      for (int p = lo; p <= hi; p++)
        portSet.insert(p);
    } else {
      int p = std::stoi(token);
      if (p >= 1 && p <= 65535)
        portSet.insert(p);
    }
  }
  return std::vector<int>(portSet.begin(), portSet.end());
}

// ─────────────────────────────────────────────
//  Save Results to File
// ─────────────────────────────────────────────
void saveResults(const ScanConfig &cfg, const std::vector<ScanResult> &results,
                 const std::string &startTime) {
  std::ofstream ofs(cfg.outputFile);
  if (!ofs.is_open()) {
    std::cerr << Color::RED
              << "\n  [!] Cannot open output file: " << cfg.outputFile
              << Color::RESET << "\n";
    return;
  }

  ofs << "TCP Port Scanner - Scan Report\n";
  ofs << "================================\n";
  ofs << "Target      : " << cfg.target << "\n";
  ofs << "IP Address  : " << cfg.resolvedIP << "\n";
  ofs << "Scan Time   : " << startTime << "\n";
  ofs << "Total Ports : " << cfg.ports.size() << "\n";
  ofs << "Threads     : " << cfg.threads << "\n";
  ofs << "Timeout     : " << cfg.timeout << " ms\n";
  ofs << "\n";
  ofs << "PORT      STATE     SERVICE      RESPONSE     BANNER\n";
  ofs << "------    -----     -------      --------     ------\n";

  for (const auto &r : results) {
    if (!r.open)
      continue;
    ofs << std::left << std::setw(10) << r.port << std::setw(10) << "OPEN"
        << std::setw(13) << r.service << std::setw(13)
        << (std::to_string(r.responseTimeMs) + " ms") << r.banner << "\n";
  }

  ofs << "\nScan Summary:\n";
  int openCnt = 0;
  for (const auto &r : results)
    if (r.open)
      openCnt++;
  ofs << "  Open ports  : " << openCnt << "\n";
  ofs << "  Total scanned: " << results.size() << "\n";

  ofs.close();
  std::cout << Color::BGREEN << "\n  [✓] Results saved to: " << cfg.outputFile
            << Color::RESET << "\n";
}

// ─────────────────────────────────────────────
//  Print Scan Table Row
// ─────────────────────────────────────────────
void printOpenPort(const ScanResult &r) {
  std::lock_guard<std::mutex> lock(g_printMtx);
  // Move cursor to new line after progress bar
  std::cout << "\r" << std::string(80, ' ') << "\r";
  std::cout << "  " << Color::BGREEN << "[OPEN]" << Color::RESET << "  "
            << Color::BWHITE << std::setw(6) << r.port << "/tcp" << Color::RESET
            << "  " << Color::BCYAN << std::setw(14) << std::left << r.service
            << Color::RESET << "  " << Color::YELLOW << std::setw(8)
            << (std::to_string(r.responseTimeMs) + "ms") << Color::RESET;

  if (!r.banner.empty()) {
    std::cout << "  " << Color::WHITE << "│ " << r.banner << Color::RESET;
  }
  std::cout << "\n";
}

void printClosedPort(const ScanResult &r) {
  std::lock_guard<std::mutex> lock(g_printMtx);
  std::cout << "\r" << std::string(80, ' ') << "\r";
  std::cout << "  " << Color::RED << "[CLSD]" << Color::RESET << "  "
            << Color::WHITE << std::setw(6) << r.port << "/tcp" << Color::RESET
            << "  " << Color::WHITE << std::setw(14) << std::left << r.service
            << Color::RESET << "\n";
}

// ─────────────────────────────────────────────
//  Main Scanner Logic
// ─────────────────────────────────────────────
void runScan(const ScanConfig &cfg) {
  g_totalPorts = (int)cfg.ports.size();
  g_scanned = 0;
  g_openCount = 0;
  g_results.clear();
  g_results.resize(g_totalPorts);

  // Table header
  std::cout << "\n";
  std::cout << Color::BWHITE
            << "  PORT        SERVICE         LATENCY   BANNER\n"
            << Color::RESET;
  std::cout
      << Color::WHITE
      << "  ----------------------------------------------------------------\n"
      << Color::RESET;

  int numThreads = std::min(cfg.threads, g_totalPorts);
  ThreadPool pool(numThreads);

  std::mutex idxMtx;

  for (int i = 0; i < g_totalPorts; i++) {
    int port = cfg.ports[i];
    int idx = i;
    pool.enqueue([&cfg, port, idx]() {
      ScanResult res = scanPort(cfg.resolvedIP, port, cfg);
      g_scanned++;

      {
        std::lock_guard<std::mutex> lock(g_resultMtx);
        g_results[idx] = res;
      }

      if (res.open) {
        printOpenPort(res);
      } else if (cfg.verboseMode) {
        printClosedPort(res);
      }

      printProgress();
    });
  }

  // Wait for all tasks to finish (pool destructor joins all threads)
}

// ─────────────────────────────────────────────
//  Print Final Summary
// ─────────────────────────────────────────────
void printSummary(const ScanConfig &cfg, long long elapsedMs) {
  int openCnt = 0;
  int closedCnt = 0;
  for (const auto &r : g_results) {
    if (r.open)
      openCnt++;
    else
      closedCnt++;
  }

  std::cout << "\n\n";
  std::cout
      << Color::WHITE
      << "  ----------------------------------------------------------------\n"
      << Color::RESET;
  std::cout << Color::BWHITE
            << "\n  +============  SCAN SUMMARY  ============+\n"
            << Color::RESET;
  std::cout << "  |  " << Color::CYAN << "Target        : " << Color::RESET
            << std::left << std::setw(26) << cfg.target << "|\n";
  std::cout << "  |  " << Color::CYAN << "IP Address    : " << Color::RESET
            << std::left << std::setw(26) << cfg.resolvedIP << "|\n";
  std::cout << "  |  " << Color::CYAN << "Ports Scanned : " << Color::RESET
            << std::left << std::setw(26) << g_totalPorts << "|\n";
  std::cout << "  |  " << Color::BGREEN << "Open Ports    : " << Color::RESET
            << std::left << std::setw(26) << openCnt << "|\n";
  std::cout << "  |  " << Color::RED << "Closed Ports  : " << Color::RESET
            << std::left << std::setw(26) << closedCnt << "|\n";
  std::cout << "  |  " << Color::YELLOW << "Duration      : " << Color::RESET
            << std::left << std::setw(26)
            << (std::to_string(elapsedMs / 1000) + "." +
                std::to_string(elapsedMs % 1000) + "s")
            << "|\n";
  std::cout << "  +=========================================+\n\n";
}

// ─────────────────────────────────────────────
//  MAIN
// ─────────────────────────────────────────────
int main(int argc, char *argv[]) {
  enableAnsiColors();
  printBanner();

  if (argc < 2) {
    printHelp(argv[0]);
    return 1;
  }

  // ── Parse Args ──
  ScanConfig cfg;
  cfg.target = argv[1];
  std::string portSpec = "1-1024"; // default

  for (int i = 2; i < argc; i++) {
    std::string arg = argv[i];
    if ((arg == "-p") && i + 1 < argc) {
      portSpec = argv[++i];
    } else if ((arg == "-t") && i + 1 < argc) {
      cfg.threads = std::min(std::stoi(argv[++i]), 500);
    } else if ((arg == "-T") && i + 1 < argc) {
      cfg.timeout = std::stoi(argv[++i]);
    } else if ((arg == "-o") && i + 1 < argc) {
      cfg.outputFile = argv[++i];
    } else if (arg == "-v") {
      cfg.verboseMode = true;
    } else if (arg == "-nb") {
      cfg.grabBanner = false;
    } else if (arg == "-h" || arg == "--help") {
      printHelp(argv[0]);
      return 0;
    }
  }

  cfg.ports = parsePorts(portSpec);
  if (cfg.ports.empty()) {
    std::cerr << Color::RED << "  [!] No valid ports specified.\n"
              << Color::RESET;
    return 1;
  }

  // ── Init Winsock ──
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    std::cerr << Color::RED << "  [!] WSAStartup failed.\n" << Color::RESET;
    return 1;
  }

  // ── Resolve Target ──
  std::cout << "  " << Color::CYAN << "[*]" << Color::RESET
            << " Resolving target: " << Color::BWHITE << cfg.target
            << Color::RESET << " ... ";
  cfg.resolvedIP = resolveHost(cfg.target);

  if (cfg.resolvedIP.empty()) {
    std::cout << Color::RED << "FAILED\n" << Color::RESET;
    std::cerr << "  [!] Cannot resolve hostname: " << cfg.target << "\n";
    WSACleanup();
    return 1;
  }
  std::cout << Color::BGREEN << cfg.resolvedIP << Color::RESET << "\n";

  // ── Print Scan Info ──
  // Get current time
  auto now = std::chrono::system_clock::now();
  auto nowT = std::chrono::system_clock::to_time_t(now);
  char timeBuf[64];
  struct tm tmInfo;
  localtime_s(&tmInfo, &nowT);
  strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", &tmInfo);

  std::cout << "  " << Color::CYAN << "[*]" << Color::RESET
            << " Scan started     : " << Color::WHITE << timeBuf << Color::RESET
            << "\n";
  std::cout << "  " << Color::CYAN << "[*]" << Color::RESET
            << " Ports to scan    : " << Color::WHITE << cfg.ports.size()
            << Color::RESET << " (" << portSpec << ")\n";
  std::cout << "  " << Color::CYAN << "[*]" << Color::RESET
            << " Threads          : " << Color::WHITE << cfg.threads
            << Color::RESET << "\n";
  std::cout << "  " << Color::CYAN << "[*]" << Color::RESET
            << " Timeout          : " << Color::WHITE << cfg.timeout << " ms"
            << Color::RESET << "\n";
  std::cout << "  " << Color::CYAN << "[*]" << Color::RESET
            << " Banner grabbing  : " << Color::WHITE
            << (cfg.grabBanner ? "enabled" : "disabled") << Color::RESET
            << "\n";

  // ── Start Scan ──
  auto scanStart = std::chrono::steady_clock::now();
  {
    runScan(cfg);
    // ThreadPool destructor is called here, joining all threads
  }
  auto scanEnd = std::chrono::steady_clock::now();
  long long elapsedMs =
      std::chrono::duration_cast<std::chrono::milliseconds>(scanEnd - scanStart)
          .count();

  // ── Print Summary ──
  printSummary(cfg, elapsedMs);

  // ── Save Output File ──
  if (!cfg.outputFile.empty()) {
    saveResults(cfg, g_results, std::string(timeBuf));
  }

  WSACleanup();
  return 0;
}
