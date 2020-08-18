# practice-2020-kuznechik
Эффективная реализация алгоритма шифрования «Кузнечик» в режиме MGM
для архитектур x86_64 и arm-v8. [Описание режима](https://tools.ietf.org/html/draft-smyshlyaev-mgm-08).
### Компиляция
Компиляция через скрипты:
* build_ref.sh
* build_sse.sh
* build_neon.sh

NEON версия может работать только на процессорах ARMv8.
