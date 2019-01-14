#ifndef NTRUENCRYPT_CRYPTOSYSTEMREGISTRY_H_
#define NTRUENCRYPT_CRYPTOSYSTEMREGISTRY_H_
#include <string>
#include <map>
#include "CryptosystemActions.h"
namespace bacrypt {
/* Класс "Реестр криптосистем". Singleton. */
class CryptosystemRegistry {
  static std::map<std::string, CryptosystemActions *> m_registry;
  CryptosystemRegistry() = default;
 public:
  static CryptosystemRegistry &instance() {
    static CryptosystemRegistry instance;
    return instance;
  }
  CryptosystemRegistry(CryptosystemRegistry const &) = delete;
  void operator=(CryptosystemRegistry const &) = delete;

  const std::map<std::string, CryptosystemActions *> &GetRegistry();
  CryptosystemActions *GetActionsFor(std::string algo);
  void Register(std::string name, CryptosystemActions *actions);
};
}  // namespace bacrypt

#endif  // NTRUENCRYPT_CRYPTOSYSTEMREGISTRY_H_
