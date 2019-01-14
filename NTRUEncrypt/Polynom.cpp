#include "Polynom.h"
#define MIN(a, b) ((a < b) ? a : b)

namespace bacrypt {

Polynom::Polynom(unsigned int degree) : m_degree(degree) {
  m_coeffs = new int[degree];
  std::fill(m_coeffs, m_coeffs + degree, 0);
}

Polynom::Polynom(unsigned int degree, int *coeffs, bool assign)
  : m_degree(degree) {
  if (assign) {
    m_coeffs = coeffs;
    return;
  }

  m_coeffs = new int[degree];
  memcpy(m_coeffs, coeffs, degree * sizeof(m_coeffs[0]));
}

Polynom::Polynom(unsigned int degree, int *coeffs) : Polynom(degree, coeffs, false) {}

Polynom::Polynom(const Polynom &other) {
  m_degree = other.m_degree;
  m_coeffs = new int[m_degree];
  for (int i = 0; i < m_degree; i++) {
    m_coeffs[i] = other.m_coeffs[i];
  }
}

int Polynom::Invert(int a, int modulo) {
  int x = 0;
  int lastx = 1;
  int y = 1;
  int lasty = 0;
  int b = modulo;
  int quotient;
  int temp;
  while (b != 0) {
    quotient = a / b;
    temp = a;
    a = b;
    b = temp % b;

    temp = x;
    x = lastx - quotient * x;
    lastx = temp;

    temp = y;
    y = lasty - quotient * y;
    lasty = temp;
  }
  if (lastx < 0) {
    lastx += modulo;
  }
  return lastx;
}

int Polynom::Mod(int input, int modulo) {
  input %= modulo;
  if (input < 0) {
    input += modulo;
  }
  return input;
}

Polynom &Polynom::operator+=(const Polynom &other) {
  for (int i = MIN(other.m_degree, m_degree) - 1; i >= 0; i--) {
    m_coeffs[i] += other.m_coeffs[i];
  }
  return *this;
}

Polynom &Polynom::operator-=(const Polynom &other) {
  for (int i = MIN(other.m_degree, m_degree) - 1; i >= 0; i--) {
    m_coeffs[i] -= other.m_coeffs[i];
  }
  return *this;
}

Polynom &Polynom::operator*=(const int multiplier) {
  for (int i = 0; i < m_degree; i++) m_coeffs[i] *= multiplier;
  return *this;
}

int Polynom::Degree(int *coeffs, int N) {
  int result = 0;
  for (int i = N - 1; i > 0; i--) {
    if (coeffs[i] != 0) {
      result = i;
      break;
    }
  }
  return result;
}

Polynom &Polynom::Convolution(const Polynom &a, const Polynom &b, int modulo) {
  int *rescoeffs = new int[a.m_degree];
  Convolution(rescoeffs, a.m_coeffs, b.m_coeffs, a.m_degree, modulo);
  return *(new Polynom(a.m_degree, rescoeffs, true));
}

Polynom &Polynom::AddAndRecenter(const Polynom &a, const Polynom &b, int lower, int modulo) {
  Polynom sum = a + b;
  Polynom *result = new Polynom(sum);
  Recenter(result->m_coeffs, result->m_degree, lower, modulo);
  return *result;
}

Polynom &Polynom::SubtractAndRecenter(const Polynom &a, const Polynom &b, int lower, int modulo) {
  Polynom *result = new Polynom(a.m_degree);
  for (int i = 0; i < a.m_degree; i++) {
    (*result)[i] = (a[i] - b[i]);
  }
  Recenter(result->m_coeffs, result->m_degree, lower, modulo);
  return *result;
}

void Polynom::Recenter(int lower, int q) {
  Recenter(m_coeffs, m_degree, lower, q);
}

Polynom *Polynom::InverseModuloPrime(int p) {
  int N = m_degree;
  int k = 0;
  int i, u;

  // Инициализация массивов коэффициентов вспомогательных полиномов
  int *b = new int[N + 1];  // b = 1 + 0x + 0x^2 + ...
  int *c = new int[N + 1];  // c = 0 + 0x + 0x^2 + ...
  int *f = new int[N + 1];  // f = {a[i] mod p}
  int *g = new int[N + 1];  // g = x^N - 1 == (p - 1) + 0x + 0x^2 + ... + x^N
  int *tmp;

  for (i = 0; i < N; i++) {
    b[i] = 0;
    c[i] = 0;
    f[i] = Mod(m_coeffs[i], p);
    g[i] = 0;
  }
  b[0] = 1;
  g[N] = 1;

  b[N] = 0;
  c[N] = 0;
  f[N] = 0;
  g[0] = p - 1;

  // Степени многочленов
  int degF = Degree(f, N);  // для f степень заранее неизвестна
  int degG = N;  // для g степень всегда равна N

  while (true) {
    while (f[0] == 0 && degF > 0) {
      // f(x) / x -- циклическое смещение элементов массива влево на один
      // c(x) * x -- циклическое смещение элементов массива вправо на один
      degF--;
      int f0 = f[0];
      int cl = c[N];
      for (i = 1; i <= N; i++) {
        f[i - 1] = f[i];
        c[N - i + 1] = c[N - i];
      }
      f[N] = f0;
      c[0] = cl;
      k++;
    }

    if (degF == 0) {
      // выйдем из цикла в код, возвращающий результат
      break;
    }

    if (degF < degG) {
      // Меняем между собой указатели (f, g) и (b, c)
      tmp = f;
      f = g;
      g = tmp;

      // Степени тоже стоит поменять местами
      if (degF != degG) degF ^= degG ^= degF ^= degG;

      tmp = b;
      b = c;
      c = tmp;
    }

    // u = (f[0] * g[0]^{-1}) mod p
    u = Mod(f[0] * Invert(g[0], p), p);

    // f(x) = (f(x) - u*g(x)) mod p
    for (i = 0; i <= N; i++) {
      f[i] = Mod(f[i] - u * g[i], p);
    }

    // b(x) = (b(x) - u*c(x)) mod p
    for (i = 0; i <= N; i++) {
      b[i] = Mod(b[i] - u * c[i], p);
    }
  }
  Polynom *result = nullptr;
  int finv = Invert(f[0], p);

  // f[0]^-1 == 0 => обратного многочлена не существует.
  if (finv != 0) {
    int shift = Mod(N - k, N);
    int *rescoeffs = new int[N];
    // rescoeffs = (x^{N-k}b(x)) mod x^N - 1
    // То есть просто со смещением в shift записываем N элементов массива b
    for (i = 0; i < N; i++) {
      rescoeffs[(i + shift) % N] = Mod(finv * b[i], p);
    }

    result = new Polynom(N, rescoeffs, true);
  }
  delete[] b;
  delete[] c;
  delete[] f;
  delete[] g;
  return result;
}

Polynom *Polynom::InverseModuloPrimePower(int p, int r) {
  Polynom *result = InverseModuloPrime(p);
  if (result == nullptr) return nullptr;

  int N = result->MaxDegree();
  int *b = result->m_coeffs;
  int *b2 = new int[N];
  int *c = new int[N];
  int q = p;

  // b = (b * (2-ab)) mod q
  do {
    q *= q;

    // c = a * b
    Convolution(c, m_coeffs, b, N, q);
    // c = 2 - a * b
    c[0] = 2 - c[0];
    c[0] += (c[0] < 0) ? q : 0;
    // q - c[i] == -c mod q
    for (int i = 1; i < N; i++) {
      c[i] = q - c[i];
    }
    // b = (b * (2-a*b)) mod q

    // Копируем b в b2
    memcpy(b2, b, sizeof(int) * N);
    if (q > r) {
      Convolution(b, b2, c, N, r);
    } else {
      Convolution(b, b2, c, N, q);
    }
  } while (q < r);
  delete[] c;
  delete[] b2;
  return result;
}

void Polynom::Convolution(int *result, int *a, int *b, int N) {
  // a и b должны быть одной степени, но проверять на это здесь мы не будем
  for (int i = 0; i < N; i++) {
    result[i] = 0;
  }

  for (int i = 0; i < N; i++) {
    for (int j = 0; j < N; j++) {
      result[(i + j) % N] += (a[i] * b[j]);
    }
  }
}

void Polynom::Recenter(int *a, int N, int lower, int q) {
  int upper = lower + q;

  for (int i = 0; i < N; i++) {
    a[i] %= q;
    if (a[i] >= upper) a[i] -= q;
    if (a[i] < lower) a[i] += q;
  }
}

void Polynom::Convolution(int *result, int *a, int *b, int N, int modulo) {
  Convolution(result, a, b, N);
  Recenter(result, N, 0, modulo);
}

Polynom::~Polynom() {
  delete[] m_coeffs;
}

Polynom operator+(Polynom left, const Polynom right) {
  return left += right;
}

Polynom operator*(const Polynom &left, const Polynom &right) {
  int *result = new int[left.m_degree];
  Polynom::Convolution(result, left.m_coeffs, right.m_coeffs, left.m_degree);
  return *(new Polynom(left.m_degree, result, true));
}

Polynom &Polynom::operator%=(int modulo) {
  for (int i = 0; i < m_degree; i++) {
    m_coeffs[i] = Mod(m_coeffs[i], modulo);
  }
  return *this;
}
}  // namespace bacrypt
