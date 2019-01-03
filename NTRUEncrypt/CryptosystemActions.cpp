#include "CryptosystemActions.h"
namespace bacrypt {
void CryptosystemActions::RegisterAction(ActionInfo info) {
  m_actions.push_back(info);
}

ActionInfo *CryptosystemActions::FindAction(const std::string &action) {
  for (auto &m_action : m_actions) {
    if (m_action.action == action) {
      return &m_action;
    }
  }
  return nullptr;
}
const std::vector<ActionInfo> &CryptosystemActions::GetActions() {
  return m_actions;
}
}  // namespace bacrypt
