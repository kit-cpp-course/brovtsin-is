#ifndef NTRUENCRYPT_CONFIGURATIONPARSER_H_
#define NTRUENCRYPT_CONFIGURATIONPARSER_H_
#include <map>
#include <string>
namespace bacrypt {

// Тип "словарь параметров"
typedef std::map<std::string, std::string> paramsmap;

// Перечисление "Состояние параметра"
enum ParameterState {
  PARAMETER_SET,       // Параметр существует и имеет значение
  PARAMETER_EMPTY,     // Параметр существует, но не имеет значения (указан как флаг)
  PARAMETER_NOT_FOUND  // Параметр не найден
};

/* Абстрактный класс парсера конфигурации */
class ConfigurationParser {
 protected:
  /* Устанавливает значение value ключа name в params в соответствии с флагом overwrite */
  void SetValue(paramsmap &params, const std::string &name, const std::string &value, const bool overwrite) {
    // Значение не найдено или установлен флаг перезаписи
    if (params.find(name) == params.end() || overwrite) params[name] = value;
  }
 public:
  /* Считывает параметры из источника конфигурации и заполняет ими params. */
  virtual void ReadParams(paramsmap &params, bool overwrite) = 0;

  /* Получение параметра key из map в value. Возвращает состояние (не найден/пуст/установлен). */
  static ParameterState GetParameter(const paramsmap &map, const std::string &key, std::string &value) {
    auto kv = map.find(key);
    if (kv == map.end()) return PARAMETER_NOT_FOUND;
    if (kv->second.empty()) return PARAMETER_EMPTY;
    value = kv->second;
    return PARAMETER_SET;
  }

  static ParameterState GetParameterState(const paramsmap &map, const std::string &key) {
    std::string value;
    return GetParameter(map, key, value);
  }
};
}  // namespace bacrypt
#endif  // NTRUENCRYPT_CONFIGURATIONPARSER_H_
