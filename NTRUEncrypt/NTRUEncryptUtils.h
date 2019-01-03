#ifndef NTRUENCRYPT_NTRUENCRYPTUTILS_H_
#define NTRUENCRYPT_NTRUENCRYPTUTILS_H_
#include <random>
#include "Polynom.h"
#include "PKCSProvider.h"

namespace bacrypt {
namespace NTRU {
/*
 * Вспомогательные методы для реализации NTRUEncrypt
 */
class NTRUEncryptUtils {
 private:
#ifdef FIXED_SEED
  // Для отладки алгоритма можно использовать ГПСЧ с фиксированным зерном
  static std::seed_seq* seed;
  static std::string seedstring;
#else
  static std::random_device *rd;
#endif
  static std::mt19937 eng;

 public:
  /* Вспомогательная функция для получения псевдослучайных чисел в интервале */
  static int Random(int min, int max);
  /* Создает случайный тернарный многочлен с numNegative элементами -1 и numPositive элементами 1 */
  static Polynom *RandomTernaryPolynom(int N, int numPositive, int numNegative);
  /* Сохраняет коэффициенты {0, 1} многочлена p в массив char */
  static char *BinaryPolynomToChar(Polynom &p);
  /* Создает массив байтов, биты которых соответствуют значениям коэффициентов многочлена p */
  static Polynom *BytesToPolynom(int read, char *buf);
  /* Проверяет на соответствие */
  static bool CheckPolynomDm0(Polynom *p, int dm0);
  /* Преобразует двоичный многочлен в троичный (с максимальной степенью degree - 1) */
  static Polynom *BinaryToTernary(const Polynom &p, unsigned int degree);
  /* Преобразует троичный многочлен в двоичный (степень вычисляется автоматически */
  static Polynom *TernaryToBinary(const Polynom &p);
};
}  // namespace NTRU
}  // namespace bacrypt
#endif  // NTRUENCRYPT_NTRUENCRYPTUTILS_H_
