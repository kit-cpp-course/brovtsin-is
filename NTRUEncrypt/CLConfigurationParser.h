#ifndef NTRUENCRYPT_CLCONFIGURATIONPARSER_H_
#define NTRUENCRYPT_CLCONFIGURATIONPARSER_H_
#include "ConfigurationParser.h"
#include <string>
namespace bacrypt {
/* Класс "парсер конфигурации из аргументов командной строки".
 * Принимает argc и argv из main в качестве аргументов в конструкторе. */
class CLConfigurationParser : protected ConfigurationParser {
  int m_argc;
  char **m_argv;
 public:
  CLConfigurationParser(int argc, char *argv[]) : m_argc(argc), m_argv(argv) {}
  void ReadParams(paramsmap &params, bool overwrite) override;
};
}  // namespace bacrypt
#endif  // NTRUENCRYPT_CLCONFIGURATIONPARSER_H_
