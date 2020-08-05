# practice-2020-kuznechik
Эффективная реализация алгоритма шифрования «Кузнечик» в режиме MGM
для архитектур x86_64 и arm-v8.
Описание режима: https://tools.ietf.org/html/draft-smyshlyaev-mgm-08 
Компиляция с помощью скриптов build_"ver".sh ; "ver" = SSE/REF/NEON
NEON версия может работать только на процессорах ARMv8.
