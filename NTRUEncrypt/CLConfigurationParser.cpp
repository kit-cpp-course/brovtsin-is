#include "CLConfigurationParser.h"
namespace bacrypt {
void CLConfigurationParser::ReadParams(paramsmap &params, bool overwrite) {
  for (int i = 1; i < m_argc; i++) {
    std::string arg(m_argv[i]);

    // Позиционные аргументы
    if (i == 1 && arg[0] != '-') {
      SetValue(params, "algo", arg, overwrite);
      continue;
    } else if (i == 2 && arg[0] != '-') {
      SetValue(params, "action", arg, overwrite);
      continue;
    }
    // Кварги
    uint64_t equalspos;
    if (arg[0] == '-' && arg[1] == '-') {
      std::string name;
      std::string value;

      if ((equalspos = arg.find('=')) != std::string::npos) {
        // Аргумент формата --argument=value
        name = arg.substr(2, equalspos - 2);
        value = arg.substr(equalspos + 1, arg.size() - equalspos + 1);
      } else {
        // Аргумент формата --argument
        name = arg.substr(2, arg.length() - 2);
        value = "";
      }
      // Игнорируем жалкие попытки перезаписать параметры
      if (name == "algo" || name == "action") continue;
      // Устанавливаем значение
      SetValue(params, name, value, overwrite);
    }
  }
}
}  // namespace bacrypt
