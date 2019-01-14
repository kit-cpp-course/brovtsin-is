#include "NTRUEncryptKeyParams.h"
#define OID(a, b, c) static_cast<int>((a) | (b) << 8 | (c) << 16)
#define OIDPTR (char*)(&oid)
namespace bacrypt {
namespace NTRU {
vector<KeyParams *> KeyParams::storage;
bool KeyParams::initialized = false;

KeyParams *NTRU::KeyParams::GetParamsByOID(char *OID) {
  for (auto &i : storage) {
    if (OID[0] == i->OID[0] &&
        OID[1] == i->OID[1] &&
        OID[2] == i->OID[2]) {
      return i;
    }
  }
  return nullptr;
}

KeyParams *NTRU::KeyParams::GetParamsByName(const string &name) {
  for (auto &i : storage) {
    if (i->name == name) {
      return i;
    }
  }
  return nullptr;
}
const vector<KeyParams *> &KeyParams::GetParams() {
  return storage;
}
void KeyParams::Initialize() {
  if (initialized) return;
  unsigned int oid;
  oid = OID(0xFF, 0x2, 0x4);
  new KeyParams("qees401ep2", OIDPTR, 401, 3, 2048, 113, 133, 71, 113, 113);
  oid = OID(0xFF, 0x3, 0x3);
  new KeyParams("qees449ep1", OIDPTR, 449, 3, 2048, 134, 149, 80, 134, 134);
  oid = OID(0xFF, 0x5, 0x3);
  new KeyParams("qees677ep1", OIDPTR, 677, 3, 2048, 157, 225, 122, 157, 157);
  oid = OID(0xFF, 0x5, 0x5);
  new KeyParams("qees1087ep2", OIDPTR, 1077, 3, 2048, 120, 362, 197, 120, 120);
}
}  // namespace NTRU
}  // namespace bacrypt
