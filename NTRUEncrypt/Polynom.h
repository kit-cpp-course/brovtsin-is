#ifndef NTRUENCRYPT_POLYNOM_H_
#define NTRUENCRYPT_POLYNOM_H_
#include <iostream>
#include <cstring>
namespace bacrypt {
/* Класс "Многочлен"
 * Имеет степень degree-1 => имеет массив коэффициентов длиной N (т.к. x^0 тоже степень, у которой может быть коэффициент)
 **/
class Polynom {
 protected:
  unsigned int m_degree;
  int *m_coeffs = nullptr;

  /* 
    Вспомогательные методы для Almost Inverse Algorithm 
  */

  /* Возвращает степень многочлена длины N с коэффициентами coeffs */
  static int Degree(int *coeffs, int N);

  /* Преобразование значений элементов массива a с длиной N в [lower, lower+q] */
  static void Recenter(int *a, int N, int lower, int q);

  /* Оператор свертки в кольце многочленов степени N. Оба многочлена должны быть одинаковой степени.
     Результат сохраняется в массив result. */
  static void Convolution(int *result, int *a, int *b, int N);

  /* Оператор свертки в кольце многочленов степени N с коэффициентами по модулю modulo.
     Оба многочлена должны быть одинаковой степени. Результат сохраняется в массив result.*/
  static void Convolution(int *result, int *a, int *b, int N, int modulo);

 public:
  /* Создает многочлен степени degree с нулевыми коэффициентами */
  explicit Polynom(unsigned int degree);
  /* Создает многочлен степени degree из массива коэффициентов coeffs. 
     Если параметр assign равен true, копирование коэффициентов в новый массив не производится. */
  Polynom(unsigned int degree, int *coeffs, bool assign);
  /* Создает многочлен степени degree, копируя коэффициенты из массива coeffs */
  Polynom(unsigned int degree, int *coeffs);
  Polynom(const Polynom &other);
  ~Polynom();

  /* Возвращает максимальную степень многочлена */
  int MaxDegree() const { return m_degree; }

  /* Возвращает a^-1 mod p. Для расчета используется расширенный алгоритм Евклида */
  static int Invert(int a, int p);

  /* Возвращает a mod p. Если результат отрицательный, превращает его в положительный. */
  static int Mod(int a, int p);

  /* Возвращает ссылку на коэффициент при степени i */
  int &operator[](int i) { return m_coeffs[i]; }
  /* Возвращает коэффициент при степени i */
  const int &operator[](int i) const { return m_coeffs[i]; }

  /* Операции для многочленов */
  friend Polynom operator+(Polynom left, Polynom right);
  /* Оператор умножения для многочленов */
  friend Polynom operator*(const Polynom &left, const Polynom &right);
  Polynom &operator+=(const Polynom &other);
  Polynom &operator-=(const Polynom &other);
  /* Домножение всех коэффициентов на множитель */
  Polynom &operator*=(int multiplier);
  /* Приведение к модулю modulo */
  Polynom &operator%=(int modulo);

  /* Возвращает указатель на массив коэффициентов */
  int *const coeffs() { return m_coeffs; }

  /* Оператор свертки в кольце многочленов степени N с коэффициентами по модулю modulo.
     Оба многочлена должны быть одинаковой степени.*/
  static Polynom &Convolution(const Polynom &a, const Polynom &b, int modulo);

  static Polynom &AddAndRecenter(const Polynom &a, const Polynom &b, int lower, int modulo);

  static Polynom &SubtractAndRecenter(const Polynom &a, const Polynom &b, int lower, int modulo);

  void Print() {
    for (int i = 0; i < m_degree; i++) {
      std::cout << m_coeffs[i] << ", ";
    }
    std::cout << std::endl;
  }

  void Recenter(int lower, int q);

  /*
    Almost Inverse Algorithm
  */

  /* Возвращает указатель на обратный многочлен mod p (или nullptr, если таковой отсутствует). 
     p -- обязательно простое число. */
  Polynom *InverseModuloPrime(int p);

  /* Возвращает указатель на обратный многочлен mod p^r (или nullptr, если таковой отсутствует).
     p -- обязательно простое число. */
  Polynom *InverseModuloPrimePower(int p, int r);
};
}  // namespace bacrypt
#endif  // NTRUENCRYPT_POLYNOM_H_
