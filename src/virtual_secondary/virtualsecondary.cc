#include <boost/algorithm/hex.hpp>
#include <boost/filesystem.hpp>
#include <fstream>

#include "crypto/crypto.h"
#include "utilities/fault_injection.h"
#include "utilities/utils.h"
#include "virtualsecondary.h"

namespace Primary {

const char* const VirtualSecondaryConfig::Type = "virtual";

VirtualSecondaryConfig::VirtualSecondaryConfig(const Json::Value& json_config) : ManagedSecondaryConfig(Type) {
  partial_verifying = json_config["partial_verifying"].asBool();
  ecu_serial = json_config["ecu_serial"].asString();
  ecu_hardware_id = json_config["ecu_hardware_id"].asString();
  full_client_dir = json_config["full_client_dir"].asString();
  ecu_private_key = json_config["ecu_private_key"].asString();
  ecu_public_key = json_config["ecu_public_key"].asString();
  firmware_path = json_config["firmware_path"].asString();
  target_name_path = json_config["target_name_path"].asString();
  metadata_path = json_config["metadata_path"].asString();
}

std::vector<VirtualSecondaryConfig> VirtualSecondaryConfig::create_from_file(
    const boost::filesystem::path& file_full_path) {
  Json::Value json_config;
  std::ifstream json_file(file_full_path.string());
  Json::parseFromStream(Json::CharReaderBuilder(), json_file, &json_config, nullptr);
  json_file.close();

  std::vector<VirtualSecondaryConfig> sec_configs;
  sec_configs.reserve(json_config[Type].size());

  for (const auto& item : json_config[Type]) {
    sec_configs.emplace_back(VirtualSecondaryConfig(item));
  }
  return sec_configs;
}

void VirtualSecondaryConfig::dump(const boost::filesystem::path& file_full_path) const {
  Json::Value json_config;

  json_config["partial_verifying"] = partial_verifying;
  json_config["ecu_serial"] = ecu_serial;
  json_config["ecu_hardware_id"] = ecu_hardware_id;
  json_config["full_client_dir"] = full_client_dir.string();
  json_config["ecu_private_key"] = ecu_private_key;
  json_config["ecu_public_key"] = ecu_public_key;
  json_config["firmware_path"] = firmware_path.string();
  json_config["target_name_path"] = target_name_path.string();
  json_config["metadata_path"] = metadata_path.string();

  Json::Value root;
  root[Type].append(json_config);

  Json::StreamWriterBuilder json_bwriter;
  json_bwriter["indentation"] = "\t";
  std::unique_ptr<Json::StreamWriter> const json_writer(json_bwriter.newStreamWriter());

  boost::filesystem::create_directories(file_full_path.parent_path());
  std::ofstream json_file(file_full_path.string());
  json_writer->write(root, &json_file);
  json_file.close();
}

VirtualSecondary::VirtualSecondary(Primary::VirtualSecondaryConfig sconfig_in)
    : ManagedSecondary(std::move(sconfig_in)) {}

bool VirtualSecondary::storeFirmware(const std::string& target_name, const std::string& content) {
  if (fiu_fail((std::string("secondary_install_") + getSerial().ToString()).c_str()) != 0) {
    return false;
  }
  Utils::writeFile(sconfig.target_name_path, target_name);
  Utils::writeFile(sconfig.firmware_path, content);
  sync();
  return true;
}

bool VirtualSecondary::getFirmwareInfo(std::string* target_name, size_t& target_len, std::string* sha256hash) {
  std::string content;

  if (!boost::filesystem::exists(sconfig.target_name_path) || !boost::filesystem::exists(sconfig.firmware_path)) {
    *target_name = std::string("noimage");
    content = "";
  } else {
    *target_name = Utils::readFile(sconfig.target_name_path.string());
    content = Utils::readFile(sconfig.firmware_path.string());
  }
  *sha256hash = boost::algorithm::to_lower_copy(boost::algorithm::hex(Crypto::sha256digest(content)));
  target_len = content.size();

  return true;
}

}  // namespace Primary
