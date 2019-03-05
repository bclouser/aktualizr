#include <gtest/gtest.h>

#include <boost/asio/io_service.hpp>
#include <boost/process.hpp>

#include "utilities/utils.h"
#include "config/config.h"

static const char* CERT_PROVIDER_PATH = nullptr;

class AktualizrCertProviderTest: public ::testing::Test {
protected:
  AktualizrCertProviderTest() {
  }

  virtual ~AktualizrCertProviderTest() {}

  virtual void SetUp() {}
  virtual void TearDown() {}


  void SpawnProcess(const char* arg = nullptr) {
    std::future<std::string> output;
    std::future<std::string> err_output;
    boost::asio::io_service io_service;
    int child_process_exit_code = -1;

    if (arg != nullptr) {
      executable_args.push_back(arg);
    }
    aktualizr_info_output.clear();

    try {
      boost::process::child aktualizr_info_child_process(
          boost::process::exe = executable_to_run, boost::process::args = executable_args,
          boost::process::std_out > output, boost::process::std_err > err_output, io_service);

      io_service.run();

      // To get the child process exit code we need to wait even in the async case (specifics of boost::process::child)
      ASSERT_TRUE(aktualizr_info_child_process.wait_for(std::chrono::seconds(20)));
      child_process_exit_code = aktualizr_info_child_process.exit_code();
    } catch (const std::exception& exc) {
      FAIL() << "Failed to spawn process " << executable_to_run << " exited with an error: " << exc.what();
    }

    ASSERT_EQ(child_process_exit_code, 0)
        << "Process " << executable_to_run << " exited with an error: " << err_output.get();

    aktualizr_info_output = output.get();
  }

protected:
  TemporaryDirectory test_dir_;

  const std::string fleet_ca_cert = "tests/test_data/CAcert.pem";
  const std::string fleet_ca_private_key = "tests/test_data/CApkey.pem";

  const std::string executable_to_run = CERT_PROVIDER_PATH;
  std::vector<std::string> executable_args = {"--fleet-ca", fleet_ca_cert, "--fleet-ca-key", fleet_ca_private_key, "-l", test_dir_.PathString(), "-g"};
  std::string aktualizr_info_output;

};

/**
 * Verifies the device key and cert generation if fleet credentials are provided
 *
 * Checks actions:
 *
 *  - [x] Use fleet credentials if provided
 */
TEST_F(AktualizrCertProviderTest, FleetCredentialsUsage) {

  const std::string path_prefix = "device_certs_dir";
  const std::string private_key_file = "pkey.pem";
  const std::string client_cert_file = "client.pem";

  // for some reason the cert-provider uses the config's base path as suffix for the local dir
  const auto private_key_file_full_path = (test_dir_ / path_prefix / private_key_file);
  const auto client_cert_file_full_path = (test_dir_ / path_prefix / client_cert_file);


  executable_args = {"--fleet-ca", fleet_ca_cert, "--fleet-ca-key", fleet_ca_private_key, "-l", test_dir_.PathString(), "-d", path_prefix};
  SpawnProcess();
  ASSERT_FALSE(aktualizr_info_output.empty());

  ASSERT_TRUE(boost::filesystem::exists(private_key_file_full_path));
  ASSERT_TRUE(boost::filesystem::exists(client_cert_file_full_path));
}

/**
 * Verifies application of paths specified in the config to the resultant key & cert file paths
 *
 * Checks actions:
 *
 *  - [x] Use file paths from config if provided
 */
TEST_F(AktualizrCertProviderTest, ConfigFilePathUsage) {

  auto test_conf_file = test_dir_ / "conf.toml";
  Config config;

  const std::string base_path = "base_path";
  const std::string private_key_file = "pkey.pem";
  const std::string client_cert_file = "client.pem";

  // for some reason the cert-provider uses the config's base path as suffix for the local dir
  const auto private_key_file_full_path = (test_dir_ / base_path / private_key_file);
  const auto client_cert_file_full_path = (test_dir_ / base_path / client_cert_file);

  config.import.base_path = base_path;
  config.import.tls_pkey_path = BasedPath(private_key_file);
  config.import.tls_clientcert_path = BasedPath(client_cert_file);

  boost::filesystem::ofstream conf_file(test_conf_file);
  config.writeToStream(conf_file);
  conf_file.close();

  SpawnProcess(test_conf_file.string().c_str());
  ASSERT_FALSE(aktualizr_info_output.empty());

  ASSERT_TRUE(boost::filesystem::exists(private_key_file_full_path));
  ASSERT_TRUE(boost::filesystem::exists(client_cert_file_full_path));
}

#ifndef __NO_MAIN__
int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);

  if (argc < 2) {
    std::cerr << "A path to the cert_provider is not specified." << std::endl;
    return  EXIT_FAILURE;
  }

  CERT_PROVIDER_PATH = argv[1];
  std::cout << "Path to the cert_provider executable: " << CERT_PROVIDER_PATH << std::endl;

  int test_run_res = RUN_ALL_TESTS();

  return test_run_res;  // 0 indicates success
}
#endif
