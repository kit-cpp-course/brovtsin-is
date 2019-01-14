#include <fstream>
#include <sstream>
#include <iostream>

#include "PKCSProvider.h"
#include "NTRUEncrypt.h"
#include "CryptosystemRegistry.h"
#include "CLConfigurationParser.h"
#include "NTRUActions.h"

using namespace std;
using namespace bacrypt;

void RegisterAlgorithmsActions() {
  CryptosystemRegistry::instance().Register("ntru", new NTRUActions());
}

int main(int argc, char *argv[]) {
  RegisterAlgorithmsActions();

  // Считываем аргументы командной строки
  CLConfigurationParser p(argc, argv);
  paramsmap map;
  p.ReadParams(map, false);

  // А можно было бы считать и из файла. Если бы мне не было лень писать это.
  // if (map.find("config") != map.end()) (read configuration from file)

  CryptosystemActions *actions = nullptr;
  bool noalgo;
  std::string algo;
  // Если алгоритм не указан
  // или алгоритм указан, но не найден
  if ((noalgo = ConfigurationParser::GetParameter(map, "algo", algo) != PARAMETER_SET) ||
      (actions = CryptosystemRegistry::instance().GetActionsFor(algo)) == nullptr) {
    if (noalgo) {
      // Если алгоритм не указан, возвращаем справку.
      cout << "Usage: " << argv[0] << " <algorithm> <action>" << endl;
    } else {
      // Если алгоритм указан, но не найден, ругаемся.
      cout << "Unknown algorithm \"" << algo << "\"." << endl;
    }

    // Выводим список поддерживаемых алгоритмов
    cout << "Supported algorithms:" << endl;
    auto registrymap = CryptosystemRegistry::instance().GetRegistry();
    for (auto &i : registrymap) {
      cout << "  - " << i.first << endl;
    }

    // Возвращаем 1, если алгоритм неизвестен
    return noalgo ? 0 : 1;
  }

  // Если действие не указано или не найдено
  std::string actionname;
  ActionInfo *action = nullptr;
  bool noaction;
  if ((noaction = ConfigurationParser::GetParameter(map, "action", actionname) != PARAMETER_SET) ||
      (action = actions->FindAction(actionname)) == nullptr) {
    if (noaction) {
      // Действие не указано => показываем справку
      cout << "Usage: " << argv[0] << " " << algo << " <action>" << endl;
    } else {
      // Действие указано, но не найдено. Ругаемся.
      cout << "Unsupported action \"" << actionname << "\"." << endl;
    }
    // Выводим список поддерживаемых действий алгоритма
    cout << "Supported actions for " << algo << ":" << endl;

    // TODO Выяснить, не теряется ли где-то здесь куча памяти.
    auto actionsvector = actions->GetActions();
    for (auto &i : actionsvector) {
      auto newline = i.description.find('\n');
      std::string shortdesc = (newline != std::string::npos) ? i.description.substr(0, newline) : i.description;
      cout << "  " << i.action << "\t\t" << shortdesc << endl;
    }
    return noaction ? 0 : 1;
  }

  // Выполняем действие, записываем результат
  bool result = (*action)(map);
  // Если false, выводим справку об использовании и возвращаем код 1.
  if (!result) {
    cout << action->action << " - " << action->description;
    return 1;
  }

  return 0;
}
