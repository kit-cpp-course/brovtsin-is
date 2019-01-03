#include "NTRUEncryptUtils.h"

namespace bacrypt {
namespace NTRU {

#ifdef FIXED_SEED
std::string NTRUEncryptUtils::seedstring = "weee";
std::seed_seq* NTRUEncryptUtils::seed = new std::seed_seq(NTRUEncryptUtils::seedstring.begin(), NTRUEncryptUtils::seedstring.end());
std::mt19937 NTRUEncryptUtils::eng = std::mt19937(NTRUEncryptUtils::seed);
#else
std::random_device *NTRUEncryptUtils::rd = new std::random_device();
std::mt19937 NTRUEncryptUtils::eng = std::mt19937((*NTRUEncryptUtils::rd)());
#endif

int NTRUEncryptUtils::Random(int min, int max) {
  std::uniform_int_distribution<> distr(min, max);
  return distr(NTRUEncryptUtils::eng);
}

Polynom *NTRUEncryptUtils::RandomTernaryPolynom(int N, int numPositive, int numNegative) {
  Polynom *result = new Polynom(N);

  while (numPositive > 0 || numNegative > 0) {
    int index = Random(0, N - 1);
    if ((*result)[index] == 0) {
      if (numPositive > 0) {
        (*result)[index] = 1;
        numPositive--;
      } else if (numNegative > 0) {
        (*result)[index] = -1;
        numNegative--;
      }
    }
  }

  return result;
}
Polynom *NTRUEncryptUtils::BytesToPolynom(int read, char *buf) {
  // Считаем степень многочлена (4 байта на длину плюс размер буфера)
  int N = (read + 4) * 8;
  // Строим пустой результирующий многочлен
  Polynom *result = new Polynom(N);
  int power = 0;

  for (int i = 0; i < read + 4; i++) {
    // Первые четыре байта возвращаем байты по адресу переменной,
    // хранящей количество считанных байт (длину сообщения)
    // После этого возвращаем байты из буфера
    unsigned char c = (i >= 4 ? buf[i - 4] : ((unsigned char *) (&read))[i]);
    // Сохраняем биты каждого байта в коэффициенты
    for (int j = 0; j < 8; j++) {
      (*result)[power] = (c & 0x80) >> 7;
      c <<= 1;
      power++;
    }
  }
  return result;
}

bool NTRUEncryptUtils::CheckPolynomDm0(Polynom *p, int dm0) {
  int N = p->MaxDegree();
  int neg = 0, pos = 0;
  for (int i = 0; i <= N; i++) {
    int value = (*p)[i];
    if (value == 1) pos++;
    if (value == -1) neg++;
  }
  return !((neg < dm0) || (pos < dm0) || (N - neg - pos) < dm0);
}

// Таблица преобразований: 3 бита в 2 трита
// 000 ==  0  0  == 0
// 001 ==  0  1  == 1
// 010 ==  0 -1  == 2
// 011 ==  1  0  == 3
// 100 ==  1  1  == 4
// 101 ==  1 -1  == 5
// 110 == -1  0  == 6
// 111 == -1  1  == 7

Polynom *NTRUEncryptUtils::BinaryToTernary(const Polynom &p, unsigned int degree) {
  // Считаем количество тритов, необходимое для сохранения битов многочлена
  int N = p.MaxDegree();
  int ceiled = ceil(N * 2 / 3.0);
  // Если сохранить в троичный многочлен требуемой степени не получается, возвращаем nullptr
  if (ceiled > degree) return nullptr;

  // Создаем массив коэффициентов троичного многочлена
  // (не удаляем, он будет использован в результирующем многочлене)
  int *tritcoeffs = new int[degree];
  std::fill(tritcoeffs, tritcoeffs + degree, 0);

  int buf = 0;
  int tritoffset = 0;
  // Верхняя граница считывания (должна быть кратна трем)
  int upperbound = ((N / 3) + ((N % 3 == 0) ? 0 : 1)) * 3;
  // Для каждых трех бит из двоичного многочлена, получаем два трита и записываем их
  for (int i = 0; i < upperbound; i++) {
    if (i < N) buf += (p[i] << (2 - (i % 3)));
    if (i != 0 && i % 3 == 2) {
      tritcoeffs[tritoffset] = buf / 3;
      tritcoeffs[tritoffset + 1] = buf % 3;
      // Смещаем [0..2] в [-1..1]
      tritcoeffs[tritoffset] -= (tritcoeffs[tritoffset] > 1) ? 3 : 0;
      tritcoeffs[tritoffset + 1] -= (tritcoeffs[tritoffset + 1] > 1) ? 3 : 0;
      // Сбрасываем буфер и увеличиваем смещение
      buf = 0;
      tritoffset += 2;
    }
  }

  return new Polynom(degree, tritcoeffs, true);
}

Polynom *NTRUEncryptUtils::TernaryToBinary(const Polynom &p) {
  // Получаем N троичного многочлена
  int N = p.MaxDegree();
  // Считаем количество бит, которые можно извлечь
  int bitcount = floor((N / 2.0) * 3);
  // Создаем массив для двоичных коэффициентов
  // (не удаляем, он будет использован в результирующем многочлене)
  int *bincoeffs = new int[bitcount];
  // Заполняем массив нулями
  std::fill(bincoeffs, bincoeffs + bitcount, 0);
  // Создаем буфер под триты
  int buf[2] = {0, 0};
  int binoffset = 0;

  // В цикле считываем по два трита
  for (int i = 0; i < N; i++) {
    buf[i % 2] = p[i];
    buf[i % 2] += (buf[i % 2] < 0 ? 3 : 0);
    if (i != 0 && i % 2 == 1) {
      // Каждые два трита извлекаем из них три бита, которые записываем в массив коэффициентов
      // (если там осталось место)
      int result = buf[0] * 3 + buf[1];
      if (binoffset < bitcount) bincoeffs[binoffset] = (result & 0x04) >> 2;
      if (binoffset + 1 < bitcount) bincoeffs[binoffset + 1] = (result & 0x02) >> 1;
      if (binoffset + 2 < bitcount) bincoeffs[binoffset + 2] = result & 0x01;
      binoffset += 3;
    }
  }

  return new Polynom(bitcount, bincoeffs, true);
}

char *NTRUEncryptUtils::BinaryPolynomToChar(Polynom &p) {
  // Получаем степень p -- это количество битов
  int N = p.MaxDegree();
  // Получаем количество байт (отбрасывая лишние биты)
  int bytes = N / 8;

  // Создаем массив под байты
  char *result = new char[bytes];
  std::fill(result, result + bytes, 0);

  // Получаем указатель на массив коэффициентов
  int *coeffs = &(p[0]);
  // Сохраняем биты в байты
  for (int i = 0; i < N; i++) {
    result[i / 8] |= (coeffs[i] << (7 - i % 8));
  }
  return result;
}
}  // namespace NTRU
}  // namespace bacrypt
