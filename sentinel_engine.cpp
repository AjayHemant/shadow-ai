#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <regex>
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <cmath>
#include "json.hpp"

using json = nlohmann::json;

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

struct ScanOutput {
    std::string payload;
    std::vector<DetectionResult> detections;
    std::string highest_severity;
    bool is_sensitive;
};

struct PolicyRule {
    std::string name;
    std::vector<std::string> severity_match;
    std::string action;
    std::string description;
};

struct PolicyDecision {
    std::string action;
    std::string reason;
    std::vector<std::string> triggered_rules;
};

std::string redact(const std::string& value) {
    if (value.length() <= 6) {
        return "***";
    }
    return value.substr(0, 3) + std::string(value.length() - 6, '*') + value.substr(value.length() - 3);
}

class SentinelEngine {
private:
    std::vector<ScanRule> rules;
    std::vector<PolicyRule> policy_rules;

    double calculate_entropy(const std::string& input) {
        if (input.empty()) return 0.0;
        
        std::unordered_map<char, size_t> frequencies;
        for (char c : input) {
            frequencies[c]++;
        }
        
        double entropy = 0.0;
        double len = static_cast<double>(input.length());
        for (const auto& pair : frequencies) {
            double p = static_cast<double>(pair.second) / len;
            entropy -= p * std::log2(p);
        }
        return entropy;
    }

    void init_detection_rules() {
        const auto opt = std::regex_constants::ECMAScript | std::regex_constants::optimize;
        const auto icase_opt = opt | std::regex_constants::icase;

        std::ifstream file("rules.json");
        if (!file.is_open()) {
            std::cerr << "[SentinelEngine] Warning: rules.json not found! Running empty rule set." << std::endl;
            return;
        }

        try {
            json j;
            file >> j;
            
            for (const auto& item : j) {
                std::string name = item.value("name", "Unknown Rule");
                std::string pattern_str = item.value("pattern", "");
                int group = item.value("group", 0);
                std::string severity = item.value("severity", "LOW");
                std::string action = item.value("action", "WARN"); // Optional if tying directly into scan logic
                std::string description = item.value("description", "");
                bool ignore_case = item.value("ignore_case", false);

                if (pattern_str.empty()) continue;

                auto flags = opt;
                if (ignore_case) {
                    flags = icase_opt;
                }

                try {
                    rules.push_back({
                        name,
                        std::regex(pattern_str, flags),
                        group,
                        severity,
                        description
                    });
                } catch (const std::regex_error& e) {
                    std::cerr << "[SentinelEngine] Error compiling regex for rule '" << name << "': " << e.what() << std::endl;
                }
            }
        } catch (const json::parse_error& e) {
            std::cerr << "[SentinelEngine] JSON Parsing Error in rules.json: " << e.what() << std::endl;
        }
    }

    void init_policy_rules() {
        policy_rules.push_back({"Block critical secrets", {"CRITICAL"}, "BLOCK", "Block any transmission containing API keys, passwords, private keys, or tokens."});
        policy_rules.push_back({"Block high-severity data", {"HIGH"}, "BLOCK", "Block transmissions with high-severity sensitive data (credit cards, SSNs, JWTs, Bearer tokens)."});
        policy_rules.push_back({"Warn on medium-severity data", {"MEDIUM"}, "WARN", "Warn when medium-severity data like emails or phone numbers are detected."});
        policy_rules.push_back({"Log low-severity data", {"LOW"}, "WARN", "Log low-severity signals such as internal IP addresses."});
    }

    std::string get_highest_severity(const std::vector<DetectionResult>& detections) {
        std::vector<std::string> order = {"CRITICAL", "HIGH", "MEDIUM", "LOW"};
        for (const auto& sev : order) {
            for (const auto& d : detections) {
                if (d.severity == sev) return sev;
            }
        }
        return "NONE";
    }

public:
    SentinelEngine() {
        init_detection_rules();
        init_policy_rules();
    }

    ScanOutput scan(const std::string& payload) {
        ScanOutput result;
        result.payload = payload;
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
                if (seen.find(key) != seen.end()) continue;
                seen.insert(key);

                DetectionResult det;
                det.data_type = rule.name;
                det.matched_value = raw;
                det.redacted_value = redact(raw);
                det.severity = rule.severity;
                det.description = rule.description;
                result.detections.push_back(det);
            }
        }

        // Entropy-based detection for arbitrary long secrets
        // We look for alphanumeric strings > 16 characters
        std::regex word_regex(R"([A-Za-z0-9+/=_\-]{16,})");
        std::sregex_iterator words_begin(payload.begin(), payload.end(), word_regex);
        std::sregex_iterator words_end;
        
        for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
            std::string word = i->str();
            double entropy = calculate_entropy(word);

            if (entropy > 4.5) {
                std::string key = "High Entropy Secret:" + word;
                if (seen.find(key) != seen.end()) continue;
                seen.insert(key);

                DetectionResult det;
                det.data_type = "High Entropy Secret";
                det.matched_value = word;
                det.redacted_value = redact(word);
                det.severity = "CRITICAL";
                det.description = "Identified via Shannon entropy (" + std::to_string(entropy) + ")";
                result.detections.push_back(det);
            }
        }

        result.is_sensitive = !result.detections.empty();
        result.highest_severity = get_highest_severity(result.detections);
        return result;
    }

    PolicyDecision evaluate(const ScanOutput& scan_result, const std::string& destination) {
        PolicyDecision decision;
        if (!scan_result.is_sensitive) {
            decision.action = "ALLOW";
            decision.reason = "No sensitive data detected.";
            return decision;
        }

        std::vector<std::string> triggered;
        std::string final_action = "ALLOW";
        std::string final_reason = "Passed all policy rules.";

        for (const auto& rule : policy_rules) {
            for (const auto& detection : scan_result.detections) {
                if (std::find(rule.severity_match.begin(), rule.severity_match.end(), detection.severity) != rule.severity_match.end()) {
                    triggered.push_back(rule.name);
                    
                    if (rule.action == "BLOCK") {
                        final_action = "BLOCK";
                        final_reason = rule.description;
                    } else if (rule.action == "WARN" && final_action != "BLOCK") {
                        final_action = "WARN";
                        final_reason = rule.description;
                    }
                }
            }
        }

        // Deduplicate triggered rules while maintaining order
        std::vector<std::string> unique_triggered;
        std::unordered_set<std::string> seen_rules;
        for (const auto& t : triggered) {
            if (seen_rules.find(t) == seen_rules.end()) {
                unique_triggered.push_back(t);
                seen_rules.insert(t);
            }
        }

        decision.action = final_action;
        decision.reason = final_reason;
        decision.triggered_rules = unique_triggered;

        return decision;
    }

    // Combine both into one call to minimize Python bridge overhead
    py::tuple process_payload(const std::string& payload, const std::string& destination) {
        ScanOutput scan_res = scan(payload);
        PolicyDecision pol_dec = evaluate(scan_res, destination);
        return py::make_tuple(scan_res, pol_dec);
    }
};

PYBIND11_MODULE(sentinel_engine_cpp, m) {
    m.doc() = "Complete C++ DLP Engine for SentinelGate";

    py::class_<DetectionResult>(m, "DetectionResult")
        .def_readonly("data_type", &DetectionResult::data_type)
        .def_readonly("matched_value", &DetectionResult::matched_value)
        .def_readonly("redacted_value", &DetectionResult::redacted_value)
        .def_readonly("severity", &DetectionResult::severity)
        .def_readonly("description", &DetectionResult::description);

    py::class_<ScanOutput>(m, "ScanOutput")
        .def_readonly("payload", &ScanOutput::payload)
        .def_readonly("detections", &ScanOutput::detections)
        .def_readonly("highest_severity", &ScanOutput::highest_severity)
        .def_readonly("is_sensitive", &ScanOutput::is_sensitive);

    py::class_<PolicyDecision>(m, "PolicyDecision")
        .def_readonly("action", &PolicyDecision::action)
        .def_readonly("reason", &PolicyDecision::reason)
        .def_readonly("triggered_rules", &PolicyDecision::triggered_rules);

    py::class_<SentinelEngine>(m, "SentinelEngine")
        .def(py::init<>())
        .def("scan", &SentinelEngine::scan)
        .def("evaluate", &SentinelEngine::evaluate)
        .def("process_payload", &SentinelEngine::process_payload);
}
