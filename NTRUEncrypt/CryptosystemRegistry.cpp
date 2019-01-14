#include "CryptosystemRegistry.h"
namespace bacrypt {

std::map<std::string, CryptosystemActions *> CryptosystemRegistry::m_registry = std::map<std::string, CryptosystemActions *>();

CryptosystemActions *CryptosystemRegistry::GetActionsFor(const std::string algo) {
  if (m_registry.find(algo) != m_registry.end()) {
    return m_registry[algo];
  }
  return nullptr;
}

void CryptosystemRegistry::Register(std::string name, CryptosystemActions *actions) {
  m_registry[name] = actions;
}

const std::map<std::string, CryptosystemActions *> &CryptosystemRegistry::GetRegistry() {
  return m_registry;
}
}  // namespace bacrypt
