#ifndef NTRUENCRYPT_NTRUENCRYPT_H_
#define NTRUENCRYPT_NTRUENCRYPT_H_
#include <iostream>
#include <ctime>
#include "Polynom.h"
#include "PKCSProvider.h"
#include "NTRUEncryptUtils.h"
#include "NTRUEncryptKeyParams.h"
#define PUBLIC_KEY_TAG 0x1
#define PRIVATE_KEY_TAG 0x2

using namespace std;

namespace bacrypt {
class NTRUActions;
namespace NTRU {

/* Структура "Заголовок публичного ключа"
 * Используется также как заголовок приватного ключа (просто с другим значением tag */
struct PUBLIC_KEY_V1_HEADER {
  char tag;
  char oidlength;
};

/* Структура "Пара ключей с параметрами"
 * Используется для удобства загрузки ключей из массивов байт */
struct KeypairWithParameters {
  Polynom *private_key = nullptr;
  Polynom *public_key = nullptr;
  KeyParams *params = nullptr;

  KeypairWithParameters() = default;
  KeypairWithParameters(KeyParams *params, Polynom *public_key, Polynom *private_key)
      : params(params), public_key(public_key), private_key(private_key) {}
};

/*
    Класс "NTRUEncrypt" реализует работу алгоритма.
*/
class NTRUEncrypt : public PKCSProvider {
  KeyParams *m_params{};
  Polynom *m_private = nullptr;
  Polynom *m_fp = nullptr;
  Polynom *m_public = nullptr;

  /* Конструктор для FromPublic и FromPrivate
   * Подразумевает, что ключи заранее проверены. */
  explicit NTRUEncrypt(KeypairWithParameters kwp)
      : m_params(kwp.params), m_public(kwp.public_key), m_private(kwp.private_key) {}

  /* Генерирует и сохраняет в текущем объекте многочлен приватного ключа,
   * записывает адрес созданного многочлена f_q в f_qptr для построения публичного ключа.
   * Возвращает результат*/
  bool GeneratePrivateKey(Polynom *&f_qptr);

  /* Генерирует и сохраняет в текущем объекте многочлен публичного ключа,
   * построенный из приватного (или f_q, если указан) */
  bool GeneratePublicKey(Polynom *f_q);

  /* Сохраняет публичный ключ в stream.
   * Параметр part_of_private устанавливает значение в заголовке ключа
   * (будет ли оно равно значению для приватного или значению для публичного ключа) */
  bool SavePublicKey(ostream &stream, bool part_of_private) const;

  /* Загружает пару ключей из stream, возвращая многочлены публичного и приватного ключа,
   * а также параметры в соответствии с указанной в заголовке сериализованного ключа
   * последовательностью OID.
   * С параметром force_public загружается только публичный ключ. */
  static KeypairWithParameters LoadKeypair(istream &stream, bool force_public);

  /* Проверяет пару ключей на формальное соответствие параметрам.
   * Эта проверка не является полной -- в случае приватного ключа,
   * возможно отсутствие обратных многочленов. */
  static bool ValidateKeypair(KeypairWithParameters kwp);

  /* Возвращает объект NTRUEncrypt с парой ключей, заданной в kwp.
   * В случае некорректной пары, возвращает nullptr; */
  static NTRUEncrypt *FromPrivate(KeypairWithParameters kwp);

 public:
  /* Создает пустой объект NTRUEncrypt. */
  NTRUEncrypt() = default;;

  /* Создает объект NTRUEncrypt с заданными параметрами ключа. Ключ не генерируется. */
  explicit NTRUEncrypt(KeyParams *params);

  /* Возвращает объект NTRUEncrypt с публичным ключом (для шифрования),
   * считываемым из потока public_key (в формате публичного ключа NTRUEncrypt).
   * Возвращает nullptr в случае некорректного ключа. */
  static NTRUEncrypt *FromPublic(istream &public_key);

  /* Возвращает объект NTRUEncrypt с публичным ключом (для шифрования),
   * заданным в форме многочлена. Возвращает nullptr в случае некорректного ключа. */
  static NTRUEncrypt *FromPublic(KeyParams *params, Polynom *public_key);

  /* Возвращает объект NTRUEncrypt с парой ключей, считываемой из потока private_key
   * (в формате приватного ключа NTRUEncrypt). Возвращает nullptr в случае некорректного ключа. */
  static NTRUEncrypt *FromPrivate(istream &private_key);

  /* Возвращает объект NTRUEncrypt с парой ключей, строящейся на основе многочлена private_key
   * Возвращает nullptr в случае некорректного ключа. */
  static NTRUEncrypt *FromPrivate(KeyParams *params, Polynom *private_key);

  /* Возвращает объект NTRUEncrypt с парой ключей public_key и private_key.
   * Возвращает nullptr в случае некорректного ключа. */
  static NTRUEncrypt *FromPrivate(KeyParams *params, Polynom *public_key, Polynom *private_key);

  /* Возвращает используемые параметры */
  KeyParams *GetParams() { return m_params; }
  /* Устанавливает используемые параметры.
   * Если параметры не совпадают со старыми, ключи обнуляются. */
  void SetParams(KeyParams *params);

  void GenerateKeypair() override;
  bool SavePrivateKey(ostream &stream) const override;
  bool SavePublicKey(ostream &stream) const override;
  bool LoadPrivateKey(istream &stream) override;
  bool LoadPublicKey(istream &stream) override;

  Polynom *public_key() { return m_public; }

  bool Encrypt(istream &input, ostream &output) const override;
  bool Decrypt(istream &input, ostream &output) const override;

  ~NTRUEncrypt() override;
};
}  // namespace NTRU
}  // namespace bacrypt
#endif // NTRUENCRYPT_NTRUENCRYPT_H_
