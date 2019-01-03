#ifndef NTRUENCRYPT_PKCSACTIONS_H_
#define NTRUENCRYPT_PKCSACTIONS_H_
#include <string>
#include <iostream>
#include <fstream>
#include <functional>
#include <utility>
#include "PKCSProvider.h"
#include "CryptosystemActions.h"

/* Класс "действия криптосистемы с открытым ключом"
 * Регистрирует (и содержит) действия "шифровать" и "расшифровать" по умолчанию */
namespace bacrypt {
class PKCSActions : public CryptosystemActions {
 protected:
  PKCSProvider *provider;

  /* Подготавливает потоки ввода-вывода в зависимости от входных параметров */
  void PrepareIO(const paramsmap &params, std::istream *&input, std::ostream *&output);
  /* Безопасно закрывает потоки ввода-вывода */
  void CloseIO(std::istream *input, std::ostream *output);
  explicit PKCSActions(std::string name);
 public:
  virtual bool EncryptAction(const paramsmap &params);
  virtual bool DecryptAction(const paramsmap &params);
  virtual bool GenerateKeysAction(const paramsmap &params);
};
}  // namespace bacrypt
#endif  // NTRUENCRYPT_PKCSACTIONS_H_
