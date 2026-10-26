#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

#include <pcap/pcap.h>

#include "packetscope/capture.hpp"

namespace {

volatile std::sig_atomic_t g_stop = 0;

void on_signal(int) { g_stop = 1; }

void print_usage() {
    std::cout << "Usage: packetscope [filter] [options]\n"
                 "  filter        what to print: all, tcp, udp, icmp, icmpv6, ipv4, ipv6, other (default all)\n"
                 "Options:\n"
                 "  -i <iface>    capture live from this interface (default: first active non-loopback)\n"
                 "  -r <file>     read packets from a .pcap file instead of a live interface\n"
                 "  -c <count>    stop after this many packets (default 100, 0 = no limit)\n"
                 "  -b <bpf>      libpcap capture filter, e.g. \"tcp port 443\"\n"
                 "  -o <file>     log printed packets to this file (default capture.log, 'none' to disable)\n"
                 "  -t <n>        port-scan alert threshold in distinct ports (default 20, 0 disables)\n"
                 "  -h            show this help\n"
                 "Live capture usually needs root: sudo ./packetscope\n";
}

std::string default_device() {
    pcap_if_t* devices = nullptr;
    char err[PCAP_ERRBUF_SIZE];
    std::string chosen;
    if (pcap_findalldevs(&devices, err) == 0) {
        for (pcap_if_t* d = devices; d != nullptr; d = d->next) {
            const bool loopback = (d->flags & PCAP_IF_LOOPBACK) != 0;
            const bool up = (d->flags & PCAP_IF_UP) != 0;
            if (!loopback && up) {
                chosen = d->name;
                break;
            }
        }
        pcap_freealldevs(devices);
    }
    return chosen.empty() ? "en0" : chosen;
}

}  // namespace

int main(int argc, char* argv[]) {
    std::string filter_name = "all";
    std::string device;
    std::string read_file;
    std::string log_path = "capture.log";
    ps::CaptureOptions options;
    std::size_t scan_threshold = 20;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto next_value = [&](const char* flag) -> const char* {
            if (i + 1 >= argc) {
                std::cerr << "error: " << flag << " needs a value\n";
                return nullptr;
            }
            return argv[++i];
        };
        if (arg == "-h" || arg == "--help") {
            print_usage();
            return 0;
        } else if (arg == "-i" || arg == "-r" || arg == "-c" || arg == "-b" || arg == "-o" || arg == "-t") {
            const char* value = next_value(arg.c_str());
            if (value == nullptr) {
                return 1;
            }
            char* end = nullptr;
            if (arg == "-i") {
                device = value;
            } else if (arg == "-r") {
                read_file = value;
            } else if (arg == "-b") {
                options.bpf = value;
            } else if (arg == "-o") {
                log_path = value;
            } else {
                const long n = std::strtol(value, &end, 10);
                if (*value == '\0' || *end != '\0' || n < 0) {
                    std::cerr << "error: " << arg << " needs a non-negative number\n";
                    return 1;
                }
                if (arg == "-c") {
                    options.max_packets = n;
                } else {
                    scan_threshold = static_cast<std::size_t>(n);
                }
            }
        } else if (!arg.empty() && arg[0] != '-') {
            filter_name = arg;
        } else {
            std::cerr << "error: unknown option " << arg << "\n";
            print_usage();
            return 1;
        }
    }

    ps::DisplayFilter filter;
    if (!ps::DisplayFilter::parse(filter_name, filter)) {
        std::cerr << "error: unknown filter '" << filter_name << "'\n";
        print_usage();
        return 1;
    }

    char error[PCAP_ERRBUF_SIZE];
    pcap_t* handle = nullptr;
    if (!read_file.empty()) {
        handle = pcap_open_offline(read_file.c_str(), error);
        if (handle == nullptr) {
            std::cerr << "Could not open " << read_file << ": " << error << "\n";
            return 1;
        }
        std::cout << "PacketScope - reading " << read_file << "\n";
    } else {
        if (device.empty()) {
            device = default_device();
        }
        handle = pcap_open_live(device.c_str(), 65535, 1, 1000, error);
        if (handle == nullptr) {
            std::cerr << "Could not open device " << device << ": " << error << "\n";
            return 1;
        }
        std::cout << "PacketScope - live capture on " << device << " (Ctrl+C to stop)\n";
        std::signal(SIGINT, on_signal);
    }

    std::ofstream log;
    if (log_path != "none") {
        log.open(log_path);
        if (!log) {
            std::cerr << "warning: could not open log file " << log_path << "; continuing without a log\n";
        } else {
            std::cout << "Logging printed packets to " << log_path << "\n";
        }
    }
    std::cout << "Display filter: " << filter.name() << "\n\n";

    ps::TrafficAnalyzer analyzer(scan_threshold);
    const ps::CaptureResult result =
        ps::run_capture(handle, options, filter, analyzer, std::cout, log.is_open() ? &log : nullptr, &g_stop);
    pcap_close(handle);

    if (!result.ok) {
        std::cerr << "error: " << result.error << "\n";
        return 1;
    }

    std::cout << "\nCapture complete.\n"
              << ps::format_summary(analyzer, filter.name()) << ps::format_top_connections(analyzer, 5)
              << ps::format_top_ports(analyzer, 5) << ps::format_scan_alerts(analyzer);
    return 0;
}
