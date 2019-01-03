#include "NTRUEncrypt.h"

namespace bacrypt {
namespace NTRU {
NTRUEncrypt::NTRUEncrypt(KeyParams *params) : m_params(params) {};

NTRUEncrypt::~NTRUEncrypt() {
  delete m_public;
  delete m_private;
  delete m_fp;
}

Polynom *NTRUEncrypt::GeneratePrivateKey(KeyParams *params, Polynom *&f_pptr, Polynom *&f_qptr) {
  Polynom *f = nullptr;
  Polynom *f_p = nullptr;
  Polynom *f_q = nullptr;

  do {
    delete f;
    delete f_p;
    delete f_q;
    // f = 1 + p*F
    f = NTRUEncryptUtils::RandomTernaryPolynom(params->N, params->df, params->df);
    (*f) *= params->p;
    (*f)[0]++;

    // Ищем f^-1 mod p и f^-1 mod q (для доказательства обратимости)
    f_p = f->InverseModuloPrime(params->p);
    f_q = f->InverseModuloPrimePower(2, params->q);
  } while (f_p == nullptr || f_q == nullptr);
  // Сохраняем f_p и f_q
  f_pptr = f_p;
  f_qptr = f_q;
  return f;
}

Polynom *NTRUEncrypt::GeneratePublicKey(KeyParams *params, Polynom *private_key, Polynom *f_q) {
  if (f_q == nullptr) {
    f_q = private_key->InverseModuloPrimePower(2, params->q);
  }

  if (f_q == nullptr) return nullptr;
  Polynom *g = nullptr;
  Polynom *ginverted = nullptr;
  do {
    delete g;
    g = NTRUEncryptUtils::RandomTernaryPolynom(params->N, params->dg + 1, params->dg);
    ginverted = g->InverseModuloPrimePower(2, params->q);
  } while (ginverted == nullptr);
  delete ginverted;

  Polynom h = *f_q * *g;
  delete f_q;
  delete g;
  for (int i = 0; i < params->N; i++) {
    h[i] = (h[i] * params->p) % params->q;
    if (h[i] < 0) {
      h[i] += params->q;
    }
  }
  return new Polynom(h);
}

void NTRUEncrypt::GenerateKeypair() {
  Polynom *new_private = nullptr;
  Polynom *new_fp = nullptr;
  Polynom *new_fq = nullptr;
  Polynom *new_public = nullptr;
  // Пытаемся создать пару ключей до тех пор, пока хотя бы одна не найдется
  // (не все многочлены имеют пригодные для использования обратные многочлены)
  do {
    delete new_private;
    delete new_fp;
    delete new_fq;
    delete new_public;
    new_private = GeneratePrivateKey(m_params, new_private, new_fp);
    new_public = GeneratePublicKey(m_params, new_private, new_fq);
  } while (new_private == nullptr || new_public == nullptr);
  // Удаляем всё, что больше не пригодится
  delete m_public;
  delete m_private;
  delete m_fp;

  // Обновляем данные
  m_private = new_private;
  m_fp = new_fp;
  m_public = new_public;
}

bool NTRUEncrypt::ValidateKeypair(KeypairWithParameters kwp) {
  // Ключей нет.
  if (kwp.public_key == nullptr && kwp.private_key == nullptr) return false;

  // Степень многочленов не совпадает с указанной в параметрах.
  if ((kwp.public_key != nullptr && kwp.public_key->MaxDegree() != kwp.params->N) ||
      (kwp.private_key != nullptr && kwp.private_key->MaxDegree() != kwp.params->N))
    return false;

  // Считаем количество положительных-отрицательных коэффициентов в приватном ключе
  if (kwp.private_key != nullptr) {
    int neg = 0;
    int pos = 0;
    int value;
    for (int i = 0; i < kwp.params->N; i++) {
      value = (*kwp.private_key)[i];
      if (value == 0) continue;
      if (value < 0) neg++; else pos++;
    }
    if (neg < kwp.params->df || pos < kwp.params->df) return false;
  }

  return true;
}

NTRUEncrypt *NTRUEncrypt::FromPublic(istream &public_key) {
  KeypairWithParameters kwp = LoadKeypair(public_key, true);
  if (ValidateKeypair(kwp)) return new NTRUEncrypt(kwp);
  return nullptr;
}

NTRUEncrypt *NTRUEncrypt::FromPublic(KeyParams *params, Polynom *public_key) {
  KeypairWithParameters kwp(params, public_key, nullptr);
  if (ValidateKeypair(kwp)) return new NTRUEncrypt(kwp);
  return nullptr;
}

NTRUEncrypt *NTRUEncrypt::FromPrivate(istream &private_key) {
  return FromPrivate(LoadKeypair(private_key, false));
}

NTRUEncrypt *NTRUEncrypt::FromPrivate(KeyParams *params, Polynom *private_key) {
  KeypairWithParameters kwp(params, nullptr, private_key);
  return FromPrivate(kwp);
}

NTRUEncrypt *NTRUEncrypt::FromPrivate(KeypairWithParameters kwp) {
  if (!ValidateKeypair(kwp)) return nullptr;

  // Дополнительно проверим на наличие обратных многочленов (и сохраним их)
  Polynom *f_p = kwp.private_key->InverseModuloPrime(kwp.params->p);
  if (f_p == nullptr) return nullptr;

  Polynom *f_q = kwp.private_key->InverseModuloPrimePower(2, kwp.params->q);
  if (f_q == nullptr) {
    delete f_p;
    return nullptr;
  }

  // Если публичный ключ не задан, получаем его
  if (kwp.public_key == nullptr) {
    Polynom *public_key = GeneratePublicKey(kwp.params, kwp.private_key, f_q);
    kwp.public_key = public_key;
  }
  // f_q нужен только на стадии генерации публичного ключа
  delete f_q;

  // Создаем новый объект NTRUEncrypt и сохраняем в него f_p
  NTRUEncrypt *result = new NTRUEncrypt(kwp);
  result->m_fp = f_p;
  return result;
}

NTRUEncrypt *NTRUEncrypt::FromPrivate(KeyParams *params, Polynom *public_key, Polynom *private_key) {
  KeypairWithParameters kwp(params, public_key, private_key);
  return FromPrivate(kwp);
}

bool NTRUEncrypt::SavePublicKey(ostream &stream) const {
  return SavePublicKey(stream, false);
}

bool NTRUEncrypt::SavePublicKey(ostream &stream, bool part_of_private) const {
  if (m_public == nullptr) return false;
  PUBLIC_KEY_V1_HEADER header;
  header.tag = part_of_private ? PRIVATE_KEY_TAG : PUBLIC_KEY_TAG;
  header.oidlength = 3;

  stream.write((const char *) &header, sizeof(header));
  stream.write((char *) m_params->OID, header.oidlength);
  stream.write((char *) (&(*m_public)[0]), m_public->MaxDegree() * sizeof((*m_public)[0]));
  return true;
}

bool NTRUEncrypt::SavePrivateKey(ostream &stream) const {
  if (m_private == nullptr) return false;

  SavePublicKey(stream, true);
  for (int i = 0; i < m_params->N; i++) {
    stream.write((char *) &((*m_private)[i]), 4);
  }
  return true;
}

bool NTRUEncrypt::LoadPrivateKey(istream &stream) {
  KeypairWithParameters kwp = LoadKeypair(stream, false);
  if (!ValidateKeypair(kwp)) return false;

  // Дополнительная валидация через нахождение f_p и f_q
  Polynom *new_fp = kwp.private_key->InverseModuloPrime(kwp.params->p);
  if (new_fp == nullptr) return false;
  Polynom *new_fq = kwp.private_key->InverseModuloPrimePower(2, kwp.params->q);
  if (new_fq == nullptr) {
    delete new_fp;
    return false;
  }
  // Удаляем предыдущие значения
  delete new_fq;
  delete m_private;
  delete m_public;
  delete m_fp;
  // m_params не удаляем!

  // Задаем новые
  m_private = kwp.private_key;
  m_public = kwp.public_key;
  m_params = kwp.params;
  return true;
}

bool NTRUEncrypt::LoadPublicKey(istream &stream) {
  KeypairWithParameters kwp = LoadKeypair(stream, true);
  if (!ValidateKeypair(kwp)) return false;

  delete m_private;
  delete m_fp;
  delete m_public;

  m_public = kwp.public_key;
  m_params = kwp.params;
  return true;
}

KeypairWithParameters NTRUEncrypt::LoadKeypair(istream &stream, bool force_public) {
  KeypairWithParameters result;
  PUBLIC_KEY_V1_HEADER keyheader;
  stream.read((char *) &keyheader, sizeof(PUBLIC_KEY_V1_HEADER));
  if (stream.gcount() != sizeof(PUBLIC_KEY_V1_HEADER)) return result;

  // Неверный формат ключа
  if (keyheader.tag != PUBLIC_KEY_TAG && keyheader.tag != PRIVATE_KEY_TAG)
    return result;

  // Загружаем заголовок oid
  char *oidbuf = new char[keyheader.oidlength];
  stream.read(oidbuf, keyheader.oidlength);
  if (stream.gcount() != keyheader.oidlength) return result;

  // Ищем такой oid
  KeyParams *newparams = KeyParams::GetParamsByOID(oidbuf);
  if (newparams == nullptr) return result;
  delete[] oidbuf;

  // Считываем коэффициенты h
  int expected_length = newparams->N * sizeof(int);
  int *h = new int[newparams->N];
  stream.read((char *) h, expected_length);
  if (stream.gcount() != expected_length) return result;

  // Сохраняем публичный ключ
  result.params = newparams;
  result.public_key = new Polynom(newparams->N, h, true);

  // Если это не приватный ключ (или нужен только публичный), можно завершать процесс.
  if (keyheader.tag != PRIVATE_KEY_TAG || force_public) return result;

  // Считываем байты приватного ключа
  int expected_f = newparams->N * sizeof(int);
  char *buf = new char[expected_f];
  stream.read(buf, expected_f);
  if (stream.gcount() != expected_f) return result;

  // Восстанавливаем f
  int *f = new int[newparams->N];
  for (int i = 0; i < newparams->N; i++) {
    f[i] = ((int *) buf)[i];
  }

  // Строим многочлен из f
  result.private_key = new Polynom(newparams->N, f, true);
  // Возвращаем результат
  return result;
}

bool NTRUEncrypt::Encrypt(istream &input, ostream &output) const {
  // NTRUEncrypt без модификаций может шифровать только ограниченное количество байт
  int bufsize = m_params->maxMsgLenBytes;

  // Готовим буфер для считывания сообщения
  char *buf = new char[bufsize];
  std::fill(buf, buf + bufsize, 0);

  // Считываем сообщение
  input.read(buf, bufsize);
  // Если ничего прочитать не удалось, возвращаем false
  int read = input.gcount();
  if (read == 0) return false;

  // Строим двоичный многочлен сообщения
  Polynom *mb = NTRUEncryptUtils::BytesToPolynom(read, buf);
  // Удаляем буфер
  delete[] buf;
  // Преобразуем в троичный многочлен
  Polynom *m = NTRUEncryptUtils::BinaryToTernary(*mb, m_params->N);
  // Удаляем двоичный многочлен
  delete mb;
  // Если в троичный многочлен последовательность такой длины уложить не получается, возвращаем false
  if (m == nullptr) {
    return false;
  }

  // Генерируем "ослепляющий" многочлен
  Polynom *r = nullptr;
  Polynom *R = nullptr;
  Polynom *prime = nullptr;
  do { // Пытаться, пока подходящий многочлен не найдется
    delete r;
    delete R;
    delete prime;
    r = NTRUEncryptUtils::RandomTernaryPolynom(m_params->N,
                                               NTRUEncryptUtils::Random(m_params->dr, m_params->dr + 50),
                                               NTRUEncryptUtils::Random(m_params->dr, m_params->dr + 50));

    // "Слепим" сообщение
    R = &Polynom::Convolution(*r, *m_public, m_params->q);
    prime = &Polynom::AddAndRecenter(*m, *R, -1, m_params->p);
  } while (!NTRUEncryptUtils::CheckPolynomDm0(prime, m_params->dm0));

  // Коэффициенты e -- результат шифрования.
  Polynom e = Polynom::AddAndRecenter(*R, *prime, 0, m_params->q);
  // Очищаем временные многочлены
  delete r;
  delete R;
  delete prime;

  // Записываем коэффициенты e в поток
  output.write((char *) &(e[0]), sizeof(e[0]) * m_params->N);
  return true;
}

bool NTRUEncrypt::Decrypt(istream &input, ostream &output) const {
  int p = m_params->p;
  int q = m_params->q;

  int expected = (m_params->N * sizeof((*m_private)[0]));

  // Считываем данные
  int *buf = new int[m_params->N];
  input.read((char *) buf, expected);
  // Если считать нужное количество байт не получилось, падаем
  if (input.gcount() < expected) {
    delete[] buf;
    return false;
  }

  // Строим многочлен входящего сообщения
  Polynom *e = new Polynom(m_params->N, buf);
  // Удаляем buf после построения многочлена
  delete[] buf;

  // Расшифровываем сообщение
  Polynom a = Polynom::Convolution(*m_private, *e, q);
  // Переводим коэффициенты в диапазон [-q/2 ... q/2 - 1]
  a.Recenter(-(q / 2) + 1, q); // +1 компенсирует наличие нуля
  // После этого приводим к mod p
  a.Recenter(-(p / 2), p);

  // После этого нужно найти маску == e - ci
  Polynom mask = Polynom::SubtractAndRecenter(*e, a, 0, m_params->q);
  // Удаляем более не нужный многочлен e
  delete e;

  // Теперь можем найти c == тернарный многочлен исходного сообщения
  Polynom c = Polynom::SubtractAndRecenter(a, mask, -1, m_params->p);
  // Преобразовываем в бинарный многочлен
  Polynom *cbin = NTRUEncryptUtils::TernaryToBinary(c);

  // Коэффициенты cbin есть коэффициенты исходного сообщения
  char *result = NTRUEncryptUtils::BinaryPolynomToChar(*cbin);
  // Удаляем cbin
  delete cbin;

  // Считываем длину сообщения из первых четырех байт
  int length = ((int *) result)[0];
  // Записываем полученный результат в поток
  output.write(result + sizeof(int), length);
  // Удаляем массив с результатом
  delete[] result;
  return true;
}
void NTRUEncrypt::SetParams(KeyParams *params) {
  // Если параметры новые, удаляем ключи.
  if (m_params != params || (m_params != nullptr && params != nullptr && m_params->name != params->name)) {
    delete m_private;
    delete m_public;
    delete m_fp;
  }
  // Задаем параметры
  m_params = params;
}
}
}
