#ifndef ASN1_HELPERS_H_
#define ASN1_HELPERS_H_

#include <stdexcept>
#include <sstream>
#include <fstream>

#include <boost/bind.hpp>
#include <boost/smart_ptr.hpp>

#include "constr_TYPE.h"

namespace Uptane {
namespace ASN1 {

class DecodeError : public std::domain_error {
 public:
  DecodeError()
      : std::domain_error("Invalid ASN.1 serialized input") {}
  virtual ~DecodeError() throw() {}
};

class EncodeError : public std::domain_error {
 public:
  EncodeError()
      : std::domain_error("Invalid ASN.1 serialized input") {}
  virtual ~EncodeError() throw() {}
};


// Deserialization
template<typename T>
boost::shared_ptr<T> xer_parse(asn_TYPE_descriptor_t &descr, const std::string &in) {
  T *obj = NULL;
  asn_dec_rval_t rval;

  rval = xer_decode(0, &descr, reinterpret_cast<void**>(&obj), in.c_str(), in.size());

  if (rval.code == RC_OK) {
    return boost::shared_ptr<T>(obj,
        boost::bind(descr.free_struct, &descr, _1, 0));
  } else {
    // decode partially created object (required by asn1c)
    descr.free_struct(&descr, obj, 0);

    throw DecodeError();
  }
}

template<typename T>
boost::shared_ptr<T> xer_parse(asn_TYPE_descriptor_t &descr, std::ifstream &in) {
  std::string buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

  return xer_parse<T>(descr, buf);
}

// Serialization
static inline int asn1_write_stream (const void *buffer, size_t size, void *arg) {
  std::string *out = static_cast<std::string*>(arg);
  *out += std::string(static_cast<const char*>(buffer), size);

  return 0;
};

std::string xer_serialize(void *v, asn_TYPE_descriptor_t *descr) {
  std::string out;
  asn_enc_rval_t rval;

  rval = xer_encode(descr, static_cast<void*>(v), XER_F_CANONICAL, asn1_write_stream, &out);

  if (rval.encoded == -1) {
    throw EncodeError();
  }

  return out;
}


}
}

#endif
