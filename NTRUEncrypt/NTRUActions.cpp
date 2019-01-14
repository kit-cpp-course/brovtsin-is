#include "NTRUActions.h"
namespace bacrypt {
NTRUActions::NTRUActions() : PKCSActions("ntru") {
  // Инициализируем предустановленные параметры
  NTRU::KeyParams::Initialize();

  ActionInfo *generate = FindAction(std::string("generate"));
  if (generate != nullptr) {
    generate->description = "Generates keypair compatible with specified standard.\n"
                            "Usage: generate --standard=<standard> --private=<output> --public=<output>\n";
  }
  provider = new NTRU::NTRUEncrypt();
}
bool NTRUActions::GenerateKeysAction(const paramsmap &params) {
  bool nostandard;
  std::string standardName;
  NTRU::KeyParams *standard = nullptr;
  if ((nostandard = ConfigurationParser::GetParameter(params, "standard", standardName) != PARAMETER_SET) ||
      (standard = NTRU::KeyParams::GetParamsByName(standardName)) == nullptr) {
    if (nostandard) {
      std::cout << "Standard is not defined." << std::endl;
    } else {
      std::cout << "Unknown standard: \"" << standardName << "\"." << std::endl;
    }

    std::cout << "Supported standards:" << std::endl;
    auto storage = NTRU::KeyParams::GetParams();
    for (auto &i : storage) {
      cout << "  - " << i->name << endl;
    }
    return true;
  }

  // Задаем provider указанный стандарт
  ((NTRU::NTRUEncrypt *) provider)->SetParams(standard);
  // Вызываем родительский метод
  return PKCSActions::GenerateKeysAction(params);
}
}  // namespace bacrypt
