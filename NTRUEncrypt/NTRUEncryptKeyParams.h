#ifndef NTRUENCRYPT_NTRUENCRYPTKEYPARAMS_H_
#define NTRUENCRYPT_NTRUENCRYPTKEYPARAMS_H_
#include <string>
#include <vector>

using namespace std;

namespace bacrypt {
namespace NTRU {
typedef unsigned short ushort;
/*
 * Класс "Параметры ключа NTRUEncrypt"
 * Все экземпляры класса хранятся в статическом storage (для поиска по OID)
 */
class KeyParams {
  static vector<KeyParams *> storage;
  static bool initialized;

 public:
  string name;
  char OID[3];
  ushort N;
  ushort p;
  ushort q;
  ushort df;
  ushort dg;
  ushort maxMsgLenBytes;
  ushort dr;
  ushort dm0;

  KeyParams() = default;
  KeyParams(const string &name, const char *_OID, ushort N, ushort p, ushort q,
            ushort df, ushort dg, ushort maxMsgLenBytes, ushort dr, ushort dm0) :
      name(name), N(N), p(p), q(q), df(df), dg(dg), maxMsgLenBytes(maxMsgLenBytes), dr(dr), dm0(dm0) {
    memcpy(OID, _OID, 3);
    storage.push_back(this);
  }

  /* Возвращает параметры по байтам OID */
  static KeyParams *GetParamsByOID(char *OID);
  /* Возвращает параметры по имени набора параметров */
  static KeyParams *GetParamsByName(const string &name);
  /* Возвращает вектор параметров */
  static const vector<KeyParams *> &GetParams();
  /* Инициализирует предустановленные параметры */
  static void Initialize();
};
}  // namespace NTRU
}  // namespace bacrypt
#endif  // NTRUENCRYPT_NTRUENCRYPTKEYPARAMS_H_
