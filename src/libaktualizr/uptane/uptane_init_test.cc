#include <gtest/gtest.h>

#include <string>

#include <boost/filesystem.hpp>

#include "httpfake.h"
#include "primary/initializer.h"
#include "primary/sotauptaneclient.h"
#include "storage/invstorage.h"
#include "utilities/utils.h"

/*
 * Check that aktualizr creates provisioning data if they don't exist already.
 */
TEST(Uptane, Initialize) {
  RecordProperty("zephyr_key", "OTA-983,TST-153");
  TemporaryDirectory temp_dir;
  auto http = std::make_shared<HttpFake>(temp_dir.Path());
  Config conf("tests/config/basic.toml");
  conf.uptane.director_server = http->tls_server + "/director";
  conf.uptane.repo_server = http->tls_server + "/repo";
  conf.tls.server = http->tls_server;
  conf.storage.path = temp_dir.Path();
  conf.provision.primary_ecu_serial = "testecuserial";

  // First make sure nothing is already there.
  auto storage = INvStorage::newStorage(conf.storage);
  std::string pkey;
  std::string cert;
  std::string ca;
  EXPECT_FALSE(storage->loadTlsCreds(&ca, &cert, &pkey));
  std::string public_key;
  std::string private_key;
  EXPECT_FALSE(storage->loadPrimaryKeys(&public_key, &private_key));

  // Initialize.
  KeyManager keys(storage, conf.keymanagerConfig());
  Initializer initializer(conf.provision, storage, http, keys, {});
  EXPECT_TRUE(initializer.isSuccessful());

  // Then verify that the storage contains what we expect.
  EXPECT_TRUE(storage->loadTlsCreds(&ca, &cert, &pkey));
  EXPECT_NE(ca, "");
  EXPECT_NE(cert, "");
  EXPECT_NE(pkey, "");
  EXPECT_TRUE(storage->loadPrimaryKeys(&public_key, &private_key));
  EXPECT_NE(public_key, "");
  EXPECT_NE(private_key, "");

  const Json::Value ecu_data = Utils::parseJSONFile(temp_dir.Path() / "post.json");
  EXPECT_EQ(ecu_data["ecus"].size(), 1);
  EXPECT_EQ(ecu_data["ecus"][0]["clientKey"]["keyval"]["public"].asString(), public_key);
  EXPECT_EQ(ecu_data["ecus"][0]["ecu_serial"].asString(), conf.provision.primary_ecu_serial);
  EXPECT_NE(ecu_data["ecus"][0]["hardware_identifier"].asString(), "");
  EXPECT_EQ(ecu_data["primary_ecu_serial"].asString(), conf.provision.primary_ecu_serial);
}

/*
 * Check that aktualizr does NOT change provisioning data if they DO exist
 * already.
 */
TEST(Uptane, InitializeTwice) {
  RecordProperty("zephyr_key", "OTA-983,TST-154");
  TemporaryDirectory temp_dir;
  auto http = std::make_shared<HttpFake>(temp_dir.Path());
  Config conf("tests/config/basic.toml");
  conf.storage.path = temp_dir.Path();
  conf.provision.primary_ecu_serial = "testecuserial";

  // First make sure nothing is already there.
  auto storage = INvStorage::newStorage(conf.storage);
  std::string pkey1;
  std::string cert1;
  std::string ca1;
  EXPECT_FALSE(storage->loadTlsCreds(&ca1, &cert1, &pkey1));
  std::string public_key1;
  std::string private_key1;
  EXPECT_FALSE(storage->loadPrimaryKeys(&public_key1, &private_key1));

  // Intialize and verify that the storage contains what we expect.
  {
    KeyManager keys(storage, conf.keymanagerConfig());
    Initializer initializer(conf.provision, storage, http, keys, {});
    EXPECT_TRUE(initializer.isSuccessful());

    EXPECT_TRUE(storage->loadTlsCreds(&ca1, &cert1, &pkey1));
    EXPECT_NE(ca1, "");
    EXPECT_NE(cert1, "");
    EXPECT_NE(pkey1, "");
    EXPECT_TRUE(storage->loadPrimaryKeys(&public_key1, &private_key1));
    EXPECT_NE(public_key1, "");
    EXPECT_NE(private_key1, "");
  }

  // Intialize again and verify that nothing has changed.
  {
    KeyManager keys(storage, conf.keymanagerConfig());
    Initializer initializer(conf.provision, storage, http, keys, {});
    EXPECT_TRUE(initializer.isSuccessful());

    std::string pkey2;
    std::string cert2;
    std::string ca2;
    EXPECT_TRUE(storage->loadTlsCreds(&ca2, &cert2, &pkey2));
    std::string public_key2;
    std::string private_key2;
    EXPECT_TRUE(storage->loadPrimaryKeys(&public_key2, &private_key2));

    EXPECT_EQ(cert1, cert2);
    EXPECT_EQ(ca1, ca2);
    EXPECT_EQ(pkey1, pkey2);
    EXPECT_EQ(public_key1, public_key2);
    EXPECT_EQ(private_key1, private_key2);
  }
}

/**
 * Check that aktualizr does not generate a pet name when device ID is
 * specified.
 */
TEST(Uptane, PetNameProvided) {
  RecordProperty("zephyr_key", "OTA-985,TST-146");
  TemporaryDirectory temp_dir;
  const std::string test_name = "test-name-123";

  /* Make sure provided device ID is read as expected. */
  Config conf("tests/config/device_id.toml");
  conf.storage.path = temp_dir.Path();
  conf.provision.primary_ecu_serial = "testecuserial";

  auto storage = INvStorage::newStorage(conf.storage);
  auto http = std::make_shared<HttpFake>(temp_dir.Path());
  KeyManager keys(storage, conf.keymanagerConfig());
  Initializer initializer(conf.provision, storage, http, keys, {});
  EXPECT_TRUE(initializer.isSuccessful());

  {
    EXPECT_EQ(conf.provision.device_id, test_name);
    std::string devid;
    EXPECT_TRUE(storage->loadDeviceId(&devid));
    EXPECT_EQ(devid, test_name);
  }

  {
    /* Make sure name is unchanged after re-initializing config. */
    conf.postUpdateValues();
    EXPECT_EQ(conf.provision.device_id, test_name);
    std::string devid;
    EXPECT_TRUE(storage->loadDeviceId(&devid));
    EXPECT_EQ(devid, test_name);
  }
}

/**
 * Check that aktualizr generates a pet name if no device ID is specified.
 */
TEST(Uptane, PetNameCreation) {
  RecordProperty("zephyr_key", "OTA-985,TST-145");
  TemporaryDirectory temp_dir;

  // Make sure name is created.
  Config conf("tests/config/basic.toml");
  conf.storage.path = temp_dir.Path();
  conf.provision.primary_ecu_serial = "testecuserial";
  boost::filesystem::copy_file("tests/test_data/cred.zip", temp_dir.Path() / "cred.zip");
  conf.provision.provision_path = temp_dir.Path() / "cred.zip";

  std::string test_name1, test_name2;
  {
    auto storage = INvStorage::newStorage(conf.storage);
    auto http = std::make_shared<HttpFake>(temp_dir.Path());
    KeyManager keys(storage, conf.keymanagerConfig());
    Initializer initializer(conf.provision, storage, http, keys, {});
    EXPECT_TRUE(initializer.isSuccessful());

    EXPECT_TRUE(storage->loadDeviceId(&test_name1));
    EXPECT_NE(test_name1, "");
  }

  // Make sure a new name is generated if the config does not specify a name and
  // there is no device_id file.
  TemporaryDirectory temp_dir2;
  {
    conf.storage.path = temp_dir2.Path();
    boost::filesystem::copy_file("tests/test_data/cred.zip", temp_dir2.Path() / "cred.zip");
    conf.provision.device_id = "";

    auto storage = INvStorage::newStorage(conf.storage);
    auto http = std::make_shared<HttpFake>(temp_dir2.Path());
    KeyManager keys(storage, conf.keymanagerConfig());
    Initializer initializer(conf.provision, storage, http, keys, {});
    EXPECT_TRUE(initializer.isSuccessful());

    EXPECT_TRUE(storage->loadDeviceId(&test_name2));
    EXPECT_NE(test_name2, test_name1);
  }

  // If the device_id is cleared in the config, but still present in the
  // storage, re-initializing the config should read the device_id from storage.
  {
    conf.provision.device_id = "";
    auto storage = INvStorage::newStorage(conf.storage);
    auto http = std::make_shared<HttpFake>(temp_dir2.Path());
    KeyManager keys(storage, conf.keymanagerConfig());
    Initializer initializer(conf.provision, storage, http, keys, {});
    EXPECT_TRUE(initializer.isSuccessful());

    std::string devid;
    EXPECT_TRUE(storage->loadDeviceId(&devid));
    EXPECT_EQ(devid, test_name2);
  }

  // If the device_id is removed from storage, but the field is still present in
  // the config, re-initializing the config should still read the device_id from
  // config.
  {
    TemporaryDirectory temp_dir3;
    conf.storage.path = temp_dir3.Path();
    boost::filesystem::copy_file("tests/test_data/cred.zip", temp_dir3.Path() / "cred.zip");
    conf.provision.device_id = test_name2;

    auto storage = INvStorage::newStorage(conf.storage);
    auto http = std::make_shared<HttpFake>(temp_dir3.Path());
    KeyManager keys(storage, conf.keymanagerConfig());
    Initializer initializer(conf.provision, storage, http, keys, {});
    EXPECT_TRUE(initializer.isSuccessful());

    std::string devid;
    EXPECT_TRUE(storage->loadDeviceId(&devid));
    EXPECT_EQ(devid, test_name2);
  }
}

/* Detect and recover from failed provisioning. */
TEST(Uptane, InitializeFail) {
  TemporaryDirectory temp_dir;
  auto http = std::make_shared<HttpFake>(temp_dir.Path());
  Config conf("tests/config/basic.toml");
  conf.uptane.director_server = http->tls_server + "/director";
  conf.uptane.repo_server = http->tls_server + "/repo";
  conf.tls.server = http->tls_server;
  conf.storage.path = temp_dir.Path();
  conf.provision.primary_ecu_serial = "testecuserial";

  auto storage = INvStorage::newStorage(conf.storage);
  KeyManager keys(storage, conf.keymanagerConfig());

  // Force a failure from the fake server.
  {
    http->provisioningResponse = ProvisioningResult::kFailure;
    Initializer initializer(conf.provision, storage, http, keys, {});
    EXPECT_FALSE(initializer.isSuccessful());
  }

  // Don't force a failure and make sure it actually works this time.
  {
    http->provisioningResponse = ProvisioningResult::kOK;
    Initializer initializer(conf.provision, storage, http, keys, {});
    EXPECT_TRUE(initializer.isSuccessful());
  }
}

/**
 * Verifies if the system hostname is used as a primary ECU hardware ID
 * if it's not specified in the configuration
 *
 * Checks actions:
 *
 * - [x] Use the system hostname as hardware ID if one is not provided
 */
TEST(Uptane, HostnameAsHardwareID) {
  TemporaryDirectory temp_dir;
  Config conf("tests/config/basic.toml");
  conf.storage.path = temp_dir.Path();

  boost::filesystem::copy_file("tests/test_data/cred.zip", temp_dir.Path() / "cred.zip");
  conf.provision.provision_path = temp_dir.Path() / "cred.zip";

  {
    auto storage = INvStorage::newStorage(conf.storage);
    auto http = std::make_shared<HttpFake>(temp_dir.Path());
    KeyManager keys(storage, conf.keymanagerConfig());

    EXPECT_TRUE(conf.provision.primary_ecu_hardware_id.empty());
    Initializer initializer(conf.provision, storage, http, keys, {});
    EXPECT_TRUE(initializer.isSuccessful());

    EcuSerials ecu_serials;
    EXPECT_TRUE(storage->loadEcuSerials(&ecu_serials));
    EXPECT_GE(ecu_serials.size(), 1);

    // A second element of the first tuple in ECU Serials tuple array is a primary hardware ID.
    // Each client of the storage class needs to know this information.
    // If it changes then corresponding changes should be done in each storage client.
    // perhaps it makes sense to introduce get/setPrimaryHardwareID method and incapsulate
    // this tech info within storage (or maybe some other entity)
    auto primaryHardwareID = ecu_serials[0].second;
    auto hostname = Utils::getHostname();
    EXPECT_EQ(primaryHardwareID, Uptane::HardwareIdentifier(hostname));
  }
}

#ifndef __NO_MAIN__
int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  logger_init();
  logger_set_threshold(boost::log::trivial::trace);
  return RUN_ALL_TESTS();
}
#endif
