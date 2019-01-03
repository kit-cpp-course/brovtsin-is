#ifndef NTRUENCRYPT_PKCSPROVIDER_H_
#define NTRUENCRYPT_PKCSPROVIDER_H_
#include<iostream>

using std::istream;
using std::ostream;

namespace bacrypt {
/*
 * Класс, описывающий абстрактную криптосистему с открытым ключом
 */
class PKCSProvider {
 protected:
  PKCSProvider() = default;

 public:
  /* Генерирует новую пару ключей, которая перезапишет уже хранящуюся в объекте. */
  virtual void GenerateKeypair() = 0;

  /* Сохраняет приватный ключ в двоичном виде в stream,
   * возвращает true в случае успеха. */
  virtual bool SavePrivateKey(ostream &stream) const = 0;

  /* Сохраняет публичный ключ в двоичном виде в stream,
   * возвращает true в случае успеха. */
  virtual bool SavePublicKey(ostream &stream) const = 0;

  /* Загружает приватный ключ в двоичном виде из stream,
   * возвращает true в случае успеха. */
  virtual bool LoadPrivateKey(istream &stream) = 0;

  /* Загружает публичный ключ в двоичном виде из stream,
   * возвращает true в случае успеха. */
  virtual bool LoadPublicKey(istream &stream) = 0;

  /* Шифрует байты из input, записывая результат в output.
   * Возвращает true в случае успеха. */
  virtual bool Encrypt(istream &input, ostream &output) const = 0;

  /* Расшифровывает байты из input, записывая результат в output.
   * Возвращает true в случае успеха */
  virtual bool Decrypt(istream &input, ostream &output) const = 0;
  virtual ~PKCSProvider() = default;
};
}  // namespace bacrypt
#endif  // NTRUENCRYPT_PKCSPROVIDER_H_
