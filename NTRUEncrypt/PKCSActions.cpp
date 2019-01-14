#include "PKCSActions.h"
namespace bacrypt {
using namespace std::placeholders;
PKCSActions::PKCSActions(std::string name) : CryptosystemActions(name) {
  RegisterAction(ActionInfo("encrypt", "Encrypts data with provided key.\n"
                                       "Usage: encrypt --(private|public)=<key> [--input=input] [--output=output]\n"
                                       "If both private and public keys provided, public key is used.\n"
                                       "Input and output are optional, defaults to stdin and stdout.\n",
                            std::bind(&PKCSActions::EncryptAction, this, _1)));
  RegisterAction(ActionInfo("decrypt", "Decrypts data with provided private key.\n"
                                       "Usage: decrypt --private=<key> [--input=input] [--output=output]\n"
                                       "Input and output are optional, defaults to stdin and stdout.\n",
                            std::bind(&PKCSActions::DecryptAction, this, _1)));
  RegisterAction(ActionInfo("generate", "Generates keypair.\n"
                                        "Usage: generate --private=<output> --public=<output>\n",
                            std::bind(&PKCSActions::GenerateKeysAction, this, _1)));
}

void PKCSActions::PrepareIO(const paramsmap &params, std::istream *&input, std::ostream *&output) {
  if (input != nullptr) {
    std::string inputPath;
    if (ConfigurationParser::GetParameter(params, "input", inputPath) != PARAMETER_SET) {
      // Файл для шифрования не указан -- хорошо, получаем из stdin
      input = &std::cin;
    } else {
      // Создаем поток ввода из указанного файла.
      std::ifstream *infile = new std::ifstream();
      infile->open(inputPath, std::ifstream::in | std::ifstream::binary);
      input = infile;
    }
  }

  if (output != nullptr) {
    std::string outputPath;
    if (ConfigurationParser::GetParameter(params, "output", outputPath) != PARAMETER_SET) {
      // Файл для вывода не указан -- выводим в stdout
      output = &std::cout;
    } else {
      // Создаем поток вывода в указанный файл.
      std::ofstream *outfile = new std::ofstream();
      outfile->open(outputPath, std::ofstream::out | std::ofstream::binary);
      output = outfile;
    }
  }
}

void PKCSActions::CloseIO(std::istream *input, std::ostream *output) {
  if (input != nullptr) {
    // Если поток ввода -- ifstream, закрываем и уничтожаем его.
    // Иначе это stdin, с которым никакие манипуляции не нужны.
    std::ifstream *inputfile = dynamic_cast<std::ifstream *>(input);
    if (inputfile != nullptr) {
      inputfile->close();
      delete input;
    }
  }

  if (output != nullptr) {
    // Если поток вывода -- ofstream, закрываем и уничтожаем его.
    // Иначе это stdout, с которым никакие манипуляции не нужны.
    std::ofstream *outputfile = dynamic_cast<std::ofstream *>(output);
    if (outputfile != nullptr) {
      outputfile->close();
      delete output;
    }
  }
}

bool PKCSActions::EncryptAction(const paramsmap &params) {
  std::string privateKeyPath;
  std::string publicKeyPath;

  bool hasPrivateKey = ConfigurationParser::GetParameter(params, "private", privateKeyPath) == PARAMETER_SET;
  bool hasPublicKey = ConfigurationParser::GetParameter(params, "public", publicKeyPath) == PARAMETER_SET;
  if (!hasPrivateKey && !hasPublicKey) {
    // Ключей нет, нечем шифровать
    std::cout << "No public or private key provided." << std::endl;
    return false;
  }

  // Выбираем ключ.
  // Если указан публичный ключ, выбираем его. Если нет, выбираем приватный ключ.
  // Логика такая: скорее всего, обладатель приватного ключа, зачем-то указавший путь к нему,
  // хочет зашифровать что-то чужим публичным ключом.
  std::ifstream key;
  std::string path = hasPublicKey ? publicKeyPath : privateKeyPath;
  key.open(path, std::ifstream::in | std::ifstream::binary);

  // Загружаем ключ
  bool loaded = (hasPublicKey) ? provider->LoadPublicKey(key) : provider->LoadPrivateKey(key);
  key.close();

  // Если ключ не удалось загрузить, выводим сообщение об ошибке и возвращаем false.
  if (!loaded) {
    std::cout << "Invalid " << (hasPublicKey ? "public" : "private") << " key provided." << std::endl;
    return false;
  }

  // Инициализируем входные и выходные потоки.
  std::istream *input;
  std::ostream *output;
  PrepareIO(params, input, output);

  // Пытаемся зашифровать сообщение
  bool encrypted = provider->Encrypt(*input, *output);

  // Закрываем и уничтожаем input и output, если они файлы
  CloseIO(input, output);

  // Если зашифровать сообщение не удалось, возвращаем false
  if (!encrypted) {
    std::cout << "Encryption error." << std::endl;
    return false;
  }

  // Успех. Возвращаем true.
  return true;
}

bool PKCSActions::DecryptAction(const paramsmap &params) {
  std::string privateKeyPath;
  if (ConfigurationParser::GetParameter(params, "private", privateKeyPath) != PARAMETER_SET) {
    // Если приватного ключа нет, расшифровывать нечем
    std::cout << "No private key provided." << std::endl;
    return false;
  }

  // Загружаем ключ
  std::ifstream key;
  key.open(privateKeyPath, std::ifstream::in | std::ifstream::binary);
  bool loaded = provider->LoadPrivateKey(key);
  key.close();

  // Если загрузить ключ не получилось, возвращаем ошибку.
  if (!loaded) {
    std::cout << "Invalid private key provided." << std::endl;
  }

  // Инициализируем входные и выходные потоки.
  std::istream *input;
  std::ostream *output;
  PrepareIO(params, input, output);

  // Пытаемся расшифровать сообщение
  bool decrypted = provider->Decrypt(*input, *output);

  // Закрываем и уничтожаем input и output, если они файлы
  CloseIO(input, output);

  // Если расшифровать сообщение не удалось, возвращаем false
  if (!decrypted) {
    std::cout << "Decryption error." << std::endl;
    return false;
  }

  // Успех. Возвращаем true.
  return true;
}

bool PKCSActions::GenerateKeysAction(const paramsmap &params) {
  // Предполагается, что дочерние объекты создадут провайдера исходя из параметров,
  // после чего вызовут этот метод.

  // Проверяем, указаны ли пути до ключей.
  std::string publicKeyPath;
  std::string privateKeyPath;
  if (ConfigurationParser::GetParameter(params, "public", publicKeyPath) != PARAMETER_SET) {
    std::cout << "Path to public key required." << std::endl;
    return false;
  }

  if (ConfigurationParser::GetParameter(params, "private", privateKeyPath) != PARAMETER_SET) {
    std::cout << "Path to private key required." << std::endl;
    return false;
  }

  // Создаем новую пару ключей
  provider->GenerateKeypair();

  // Вывод ключей всегда происходит в файлы. Просто потому, что файла два, а stdout один.
  std::ofstream privatefile;
  privatefile.open(privateKeyPath, std::ofstream::out | std::ofstream::binary);

  std::ofstream publicfile;
  publicfile.open(publicKeyPath, std::ofstream::out | std::ofstream::binary);

  // Пытаемся сохранить приватный ключ
  bool privatesaved = provider->SavePrivateKey(privatefile);
  privatefile.close();

  // Если сохранить приватный ключ не удалось, нет смысла сохранять публичный.
  if (!privatesaved) {
    std::cout << "Unable to save private key." << std::endl;
    publicfile.close();
    return false;
  }

  // Пытаемся сохранить публичный ключ.
  bool publicsaved = provider->SavePublicKey(publicfile);
  publicfile.close();

  if (!publicsaved) {
    std::cout << "Unable to save public key." << std::endl;
    return false;
  }

  // Успех. Возвращаем true.
  return true;
}
}