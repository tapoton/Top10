# A02:2021 – Ошибки Криптографии    ![icon](assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
| :---------: | :----------------: | :----------------: | :------------------: | :-----------------: | :----------: | :----------: | :---------------: | :--------: |
|     29      |       46.44%       |       4.49%        |         7.29         |        6.81         |    79.33%    |    34.85%    |      233,788      |   3,075    |

## Overview

Shifting up one position to #2, previously known as *Sensitive Data
Exposure*, which is more of a broad symptom rather than a root cause,
the focus is on failures related to cryptography (or lack thereof).
Which often lead to exposure of sensitive data. Notable Common Weakness Enumerations (CWEs) included
are *CWE-259: Use of Hard-coded Password*, *CWE-327: Broken or Risky
Crypto Algorithm*, and *CWE-331 Insufficient Entropy* .

## Описание

В первую очередь необходимо определить необходимость защиты данных при передаче и хранении. Так, пароли, номера кредитных карт, записи о здоровье, личная информация, а так же бизнес-секреты требуют дополнительной защиты, особенно, если эти данные попадают под законы о конфиденциальности, такие как Общие положения о защите данных (GDPR), или нормативные требования, например, о защите финансовой информации, такие как стандарт безопасности данных индустрии платёжных карт (PCI DSS). Для таких данных:

-   Передаются ли данные открытым текстом? Это касается таких протоколов, как HTTP, SMTP, FTP, также использующих расширения протокола TLS, такие, как STARTTLS. Внешний интернет-трафик опасен. Также необходимо проверять весь внутренний трафик, например, при передаче между балансировщиками нагрузки, веб-серверами или системами сервера.

-   Используются ли старые или слабые криптографические алгоритмы и протоколы по умолчанию или в старом коде?

-   Используются ли криптографические ключи по умолчанию? Генерируются или переиспользуются слабые криптографические ключи? Отсутствует ли корректное управление ключами и ротация ключей? Добавлены ли криптографические ключи в систему контроля версий вместе с исходным кодом?

-   Возможно ли не использовать шифрование? Например, отсутствуют ли директивы безопасности или HTTP-заголовки?

-   Корректно ли проверяется сертификат сервера и цепочка доверия?

-   Игнорируются или переиспользуются инициализационные векторы? Или генерируются недостаточно безопасно (например, в режиме ECB)? Используется ли обычное шифрование, когда необходимо аутентифицированное шифрование?

-   Используются ли пароли в качестве криптографических ключей из-за отсутствия функции формирования ключей.

-   Используется ли для криптографии генератор случайных чисел, который не удовлетворяет требованиям криптографии? Если выбрана корректная функция, должен ли разработчик задавать стартовое значение? Если нет, то переопределил ли разработчик механизм создания стартового значения так, что его способ не обладает достаточной энтропией? 

-   Используются ли нежелательные функции хэширования, такие как MD5, SHA1. Используются ли некриптостойкие функции хэширования там, где нужны криптостойкие?

-   Используются ли нежелательне методы криптографического дополнения, такие как PCKS #1 v1.5?

-   Содержат ли сообщения об ошибках криптографии данные, которые можно использовать, например, для padding oracle attack?

See ASVS Crypto (V7), Data Protection (V9), and SSL/TLS (V10)

## Как предотвратить

Do the following, at a minimum, and consult the references:

-   Классифицировать данные, обрабатываемые, хранимые или передаваемые приложением. Выявить, какие данные являются конфиденциальными согласно законам о конфиденциальности, нормативным требованиям или потребностям бизнеса.

-   Не хранить ненужные конфиденциальные данные. Удалять их сразу или использовать токенизацию или даже усечение, совместимые с PCI DSS. Данные, которые не хранятся, не могут быть украдены.

-   Убедиться, что все хранимые конфиденциальные данные шифруются.

-   Убедиться, что используются актуальные алгоритмы и протоколы, а ключи находятся на своих местах. Используйте надлежащее управление ключами.

-   Шифровать все данные и передавайте их с использованием безопасных протоколов, таких как TLS с шифрами с прямой секретностью, приоритезации шифров на сервере и параметров безопасности. Обеспечивать шифрование использованием таких директив, как HTTP Strict Transport Security (HSTS).

-   Отключать кэширование для ответов, которые содержат конфиденциальные данные.

-   Применять требуемый контроль безопасности
-   Apply required security controls as per the data classification.

-   Не использовать устаревшие протоколы, такие как FTP и SMTP для передачи конфиденциальных данных.

-   Хранить пароли, используя сильные адаптивные функции хэширования с солью
-   Store passwords using strong adaptive and salted hashing functions
    with a work factor (delay factor), such as Argon2, scrypt, bcrypt or
    PBKDF2.

-   Инициализационные векторы должны выбираться согласно режиму шифрования. Для многих режимов это означает использование CSPRNG (криптостойкий генератор псевдослучайных чисел). Для режимов, которые требуют токен нет необходимости в CSPRNG. В любом случае инициализационный вектор не должен использоваться дважды для фиксированного ключа.
-   Initialization vectors must be chosen appropriate for the mode of
    operation.  For many modes, this means using a CSPRNG (cryptographically
    secure pseudo random number generator).  For modes that require a
    nonce, then the initialization vector (IV) does not need a CSPRNG.  In all cases, the IV
    should never be used twice for a fixed key.

-   Всегда использовать аутентифицированное шифрование вместо обычного.

-   Ключи должны быть сгенерированы криптографически стойким генератором случайных чисел и храниться в памяти как массивы байт. Если используется пароль, то для превращения его в ключ необходимо использовать подходящую функцию выведения ключа.

-   Необходимо убедиться, что везде, где это необходимо, должен быть использован криптографически стойкий генератор случайных чисел, а так же что в качестве начального состояния выбирается число, которое невозможно предсказать. Большинство современных интерфейсов не требуют передавать начальное состояние в криптостойкий ГПСЧ.

-   Необходимо избегать устаревшие криптографические функции и схемы дополнения, такие как MD5, SHA1, PKCS #1 v1.5.

-   Необходимо проверять эффективность конфигурации и настроек независимо друг от друга.

## Примеры сценариев атак

**Сценарий #1**: Приложение шифрует номера кредитных карт в базе данных используя шифрование базы данных по умолчанию. Однако, эти данные автоматически расшифровываются при получении их из базы, что позволяет пройти SQL инъекции, в результате которой будут номера карт будут получены в виде открытого текста.

**Сценарий #2**: Сайт не следит за использованием TLS или поддерживает слабое шифрование. Злоумышленник просматривает сетевой трафик (например в небезопасной беспроводной сети), переводит соединение с HTTPs на HTTP, перехватывает запросы и крадёт сессионные куки пользователя. Затем злоумышленник повторяет куки пользователя и крадёт пользовательскую сессию, получая доступ к пользовательским приватным данным. Так же злоумышленник может изменять передаваемые данные, например, получателя денежных средств.

**Сценарий #3**: База паролей использует простое хэширование или хэширование без соли. Брешь в сценарии загрузки вайлов позволяет злоумышленник получить базу паролей. Все хэши могут быть расшифрованы при помощи радужных таблиц с заранее вычисленными хэшами. Хэши, сгенерированные простыми или быстрыми хэш-функциями можно взломать при помощи GPU, даже если они были сгенерированы с солью.

## References

-   [OWASP Proactive Controls: Protect Data
    Everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)

-   [OWASP Application Security Verification Standard (V7,
    9, 10)](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Cheat Sheet: Transport Layer
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: User Privacy
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Password and Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

-   [OWASP Cheat Sheet:
    HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

-   [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)


## List of Mapped CWEs

[CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)

[CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

[CWE-310 Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)

[CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

[CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

[CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)

[CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)

[CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)

[CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)

[CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

[CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

[CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

[CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

[CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

[CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)

[CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)

[CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

[CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

[CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)

[CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)

[CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

[CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)

[CWE-720 OWASP Top Ten 2007 Category A9 - Insecure Communications](https://cwe.mitre.org/data/definitions/720.html)

[CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)

[CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)

[CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)

[CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)

[CWE-818 Insufficient Transport Layer Protection](https://cwe.mitre.org/data/definitions/818.html)

[CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
