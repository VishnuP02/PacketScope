#include "packetscope/capture.hpp"

namespace ps {

CaptureResult run_capture(pcap_t* handle, const CaptureOptions& options, const DisplayFilter& filter,
                          TrafficAnalyzer& analyzer, std::ostream& out, std::ostream* log,
                          const volatile std::sig_atomic_t* stop_flag) {
    CaptureResult result;
    if (handle == nullptr) {
        result.ok = false;
        result.error = "no capture handle";
        return result;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        result.ok = false;
        result.error = "only Ethernet captures are supported";
        return result;
    }
    if (!options.bpf.empty()) {
        bpf_program program;
        if (pcap_compile(handle, &program, options.bpf.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
            result.ok = false;
            result.error = std::string("invalid capture filter: ") + pcap_geterr(handle);
            return result;
        }
        const int rc = pcap_setfilter(handle, &program);
        pcap_freecode(&program);
        if (rc != 0) {
            result.ok = false;
            result.error = std::string("could not apply capture filter: ") + pcap_geterr(handle);
            return result;
        }
    }

    long seen = 0;
    while (options.max_packets == 0 || seen < options.max_packets) {
        if (stop_flag != nullptr && *stop_flag != 0) {
            break;
        }
        pcap_pkthdr* header = nullptr;
        const u_char* data = nullptr;
        const int rc = pcap_next_ex(handle, &header, &data);
        if (rc == 0) {
            continue;  // live capture read timeout; check the stop flag and keep waiting
        }
        if (rc == PCAP_ERROR_BREAK) {
            break;  // end of the capture file
        }
        if (rc < 0) {
            result.ok = false;
            result.error = std::string("capture error: ") + pcap_geterr(handle);
            return result;
        }

        ++seen;
        const ParsedPacket packet = parse_ethernet(data, header->caplen);
        analyzer.record(packet, header->len);
        if (filter.matches(packet)) {
            const std::string line = format_packet_line(analyzer.stats().total, header->len, packet);
            out << line << "\n";
            if (log != nullptr) {
                *log << line << "\n";
            }
        }
    }
    return result;
}

}  // namespace ps
