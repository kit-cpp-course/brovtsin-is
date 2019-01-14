#ifndef NTRUENCRYPT_CRYPTOSYSTEMACTIONS_H_
#define NTRUENCRYPT_CRYPTOSYSTEMACTIONS_H_
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <functional>
#include <utility>
#include "ConfigurationParser.h"

namespace bacrypt {
typedef std::function<bool(const paramsmap &)> boundaction;

class ActionInfo;

/* Класс "действия криптосистемы" */
class CryptosystemActions {
 protected:
  std::string m_name;
  std::vector<ActionInfo> m_actions;
 public:
  explicit CryptosystemActions(std::string name) : m_name(std::move(name)) {}
  CryptosystemActions(std::string &name, std::vector<ActionInfo> &actions)
      : m_name(std::move(name)), m_actions(std::move(actions)) {}

  const std::vector<ActionInfo> &GetActions();
  ActionInfo *FindAction(const std::string &action);

  void RegisterAction(ActionInfo info);
};

class ActionInfo {
 public:
  std::string action;
  std::string description;
  boundaction func;

  ActionInfo() = default;
  ActionInfo(std::string _action, const std::string &_description, boundaction _func)
      : action(std::move(_action)), description(std::move(_description)), func(std::move(_func)) {}
  bool operator()(const paramsmap &p) { return func(p); }
};

}
#endif  // NTRUENCRYPT_CRYPTOSYSTEMACTIONS_H_
