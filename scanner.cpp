#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <regex>
#include <string>
#include <vector>
#include <unordered_set>

namespace py = pybind11;

struct DetectionResult {
    std::string data_type;
    std::string matched_value;
    std::string redacted_value;
    std::string severity;
    std::string description;
};

struct ScanRule {
    std::string name;
    std::regex pattern;
    int group;
    std::string severity;
    std::string description;
};

std::string redact(const std::string& value) {
    if (value.length() <= 6) {
        return "***";
    }
    return value.substr(0, 3) + std::string(value.length() - 6, '*') + value.substr(value.length() - 3);
}

class FastScanner {
private:
    std::vector<ScanRule> rules;

public:
    FastScanner() {
        // Initialize rules
        rules.push_back({"OpenAI API Key", std::regex(R"(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})"), 0, "CRITICAL", "OpenAI API key detected (sk- prefix)"});
        rules.push_back({"Anthropic API Key", std::regex(R"(sk-ant-[A-Za-z0-9_\-]{20,})"), 0, "CRITICAL", "Anthropic Claude API key detected"});
        rules.push_back({"HuggingFace Token", std::regex(R"(hf_[A-Za-z0-9]{30,})"), 0, "CRITICAL", "HuggingFace API token detected"});
        rules.push_back({"API Key (Generic)", std::regex(R"((api[_\-]?key|apikey|api[_\-]?token|secret[_\-]?key|access[_\-]?token)[^\w]*[=:"'\ms]+([\w\-\.]{16,}))", std::regex::icase), 2, "CRITICAL", "Generic API key or token detected"});
        rules.push_back({"AWS Access Key", std::regex(R"(\b(AKIA[0-9A-Z]{16})\b)"), 1, "CRITICAL", "AWS Access Key ID detected"});
        rules.push_back({"AWS Secret Key", std::regex(R"(aws[_\-]?secret[_\-]?access[_\-]?key[^\w]*([A-Za-z0-9/+=]{40}))", std::regex::icase), 1, "CRITICAL", "AWS Secret Access Key detected"});
        rules.push_back({"Private Key (PEM)", std::regex(R"(-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)"), 0, "CRITICAL", "PEM private key block detected"});
        rules.push_back({"Password in Payload", std::regex(R"((password|passwd|pwd)[^\w]*[=:"' ]+([^\s"'&,;]{6,}))", std::regex::icase), 2, "HIGH", "Password field value detected in payload"});
        rules.push_back({"Bearer Token", std::regex(R"(bearer\s+([A-Za-z0-9\-._~+/]+=*))", std::regex::icase), 1, "HIGH", "HTTP Bearer token detected"});
        rules.push_back({"Credit Card Number", std::regex(R"(\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b)"), 0, "HIGH", "Credit card number pattern detected"});
        rules.push_back({"Social Security Number", std::regex(R"(\b\d{3}-\d{2}-\d{4}\b)"), 0, "HIGH", "US Social Security Number detected"});
        rules.push_back({"Email Address", std::regex(R"(\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b)"), 0, "MEDIUM", "Email address detected in payload"});
        rules.push_back({"IPv4 Address (Private)", std::regex(R"(\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b)"), 1, "LOW", "Internal/private IP address detected"});
        rules.push_back({"Phone Number", std::regex(R"(\b(\+?1?\s?)?(\(?\d{3}\)?[\s.\-]?)(\d{3}[\s.\-]?\d{4})\b)"), 0, "MEDIUM", "Phone number detected in payload"});
        rules.push_back({"JWT Token", std::regex(R"(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)"), 0, "HIGH", "JSON Web Token (JWT) detected"});
        // GitHub Token pattern adjusted for std::regex
        rules.push_back({"GitHub Token", std::regex(R"(gh[pousr]_[A-Za-z0-9_]{36,})"), 0, "CRITICAL", "GitHub personal access token detected"});
        rules.push_back({"Slack Token", std::regex(R"(xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24})"), 0, "CRITICAL", "Slack API token detected"});
        rules.push_back({"Google API Key", std::regex(R"(AIza[0-9A-Za-z\-_]{35})"), 0, "CRITICAL", "Google API key detected"});
    }

    std::vector<DetectionResult> scan(const std::string& payload) {
        std::vector<DetectionResult> results;
        std::unordered_set<std::string> seen;

        for (const auto& rule : rules) {
            std::sregex_iterator words_begin = std::sregex_iterator(payload.begin(), payload.end(), rule.pattern);
            std::sregex_iterator words_end = std::sregex_iterator();

            for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
                std::smatch match = *i;
                std::string raw;
                
                if (rule.group >= 0 && static_cast<size_t>(rule.group) < match.size()) {
                    raw = match.str(rule.group);
                } else {
                    raw = match.str(0);
                }

                if (raw.empty()) continue;

                std::string key = rule.name + ":" + raw;
                if (seen.find(key) != seen.end()) {
                    continue;
                }
                seen.insert(key);

                DetectionResult det;
                det.data_type = rule.name;
                det.matched_value = raw;
                det.redacted_value = redact(raw);
                det.severity = rule.severity;
                det.description = rule.description;
                results.push_back(det);
            }
        }
        return results;
    }
};

PYBIND11_MODULE(sentinel_scanner, m) {
    m.doc() = "High performance C++ pattern scanner for SentinelGate";

    py::class_<DetectionResult>(m, "DetectionResult")
        .def_readonly("data_type", &DetectionResult::data_type)
        .def_readonly("matched_value", &DetectionResult::matched_value)
        .def_readonly("redacted_value", &DetectionResult::redacted_value)
        .def_readonly("severity", &DetectionResult::severity)
        .def_readonly("description", &DetectionResult::description);

    py::class_<FastScanner>(m, "FastScanner")
        .def(py::init<>())
        .def("scan", &FastScanner::scan, "Scan a payload string for sensitive data");
}
