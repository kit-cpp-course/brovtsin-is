#ifndef NTRUENCRYPT_NTRUACTIONS_H_
#define NTRUENCRYPT_NTRUACTIONS_H_
#include "NTRUEncrypt.h"
#include "NTRUEncryptKeyParams.h"
#include "PKCSActions.h"
#include <string>
namespace bacrypt {
/* Класс "Действия алгоритма NTRUEncrypt" */
class NTRUActions : public PKCSActions {
 public:
  NTRUActions();
  /* Действие "создать пару ключей" дополняется выбором параметров ключа */
  bool GenerateKeysAction(const paramsmap &params) override;
};
}

#endif  // NTRUENCRYPT_NTRUACTIONS_H_
