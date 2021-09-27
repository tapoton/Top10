# A07:2021 – Identification and Authentication Failures    ![icon](assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"}

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
| :---------: | :----------------: | :----------------: | :------------------: | :-----------------: | :----------: | :----------: | :---------------: | :--------: |
|     22      |       14.84%       |       2.55%        |         7.40         |        6.50         |    79.51%    |    45.72%    |      132,195      |   3,897    |

## Overview

Previously known as *Broken Authentication*, this category slid down
from the second position and now includes Common Weakness 
Enumerations (CWEs) related to identification
failures. Notable CWEs included are *CWE-297: Improper Validation of
Certificate with Host Mismatch*, *CWE-287: Improper Authentication*, and
*CWE-384: Session Fixation*.

## Description 

Подтверждение личности пользователя, аутентификация и управление сессиями играют важную роль в защите от атак, связанных с аутентификацией. Приложение имеет недостатки в аутентификации, если:

-   Допускается проведение автоматизированных атак, например, на учетные записи, когда у атакующего есть список действующих имен и паролей пользователей.

-   Допускается проведение атак методом подбора или других автоматизированных атак.

-   Допускается использование стандартных, ненадежных или хорошо известных паролей, например "Password1" или "admin/admin".

-   Используются ненадежные или неэффективные методы восстановления учетных данных и паролей, например "ответы на основе знаний", которые являются небезопасными.

-   используются незашифрованные, зашифрованные или ненадежно хешированные пароли (см. **A02:2021-Cryptographic Failures**).

-   Отсутствует или является неэффективной многофакторная аутентификация.

-   Отображаются идентификаторы сессии в URL.

-   Не меняются идентификаторы сессий после успешного входа в систему.

-   Некорректно аннулируются идентификаторы сессий. Пользовательские
сессии или токены аутентификации (в частности, токены единого входа (SSO)) неправильно аннулируются при выходе из системы или бездействии

## Как предотвратить

-   Где это возможно, реализуйте многофакторную аутентификацию для предотвращения автоматизированных атак, атак на учетные записи и методом подбора, а также повторного использования украденных учетных данных.

-   Не используйте создаваемые по умолчанию (стандартные) учетные данные, особенно для администраторов.

-   Реализуйте проверку надежности паролей, например проверяя вновь создаваемые или изменяемые пароли по списку "10000 наихудших паролей".

-   Установите длину, сложность и периодичность смены паролей в соответствии с руководством NIST 800-63 B (раздел 5.1.1 "Запоминаемые секреты") или любой другой современной парольной политикой.

-   Обеспечьте защиту регистрации, восстановления учетных данных и API от атак методом перечисления, используя во всех ответах одинаковые сообщения.

-   Ограничьте или значительно увеличьте интервал между неудачными попытками входа. Регистрируйте все неудачные попытки и уведомляйте администраторов при обнаружении атак на учетные данные, методом подбора или любых других атак.

-   Используйте менеджеры сессий на стороне сервера, надежные, встроенные, генерирующие после входа в систему новые, случайные идентификаторы с высокой степенью энтропии. Идентификаторы сессий не должны присутствовать в URL, а должны безопасно храниться и аннулироваться после выхода из системы, простоя или наступления абсолютного тайм-аута.

## Примеры сценариев атак

**Сценарий #1:** Атака на учетные записи с использованием списков известных паролей является очень распространенной. Если в приложении нет защиты от автоматизированных атак или атак на учетные записи, то оно может быть использовано для определения действующих учетных данных.

**Сценарий #2:** Большинство атак на аутентификацию связано с использованием исключительно паролей. Ранее считавшиеся хорошими требования к смене пароля и его сложности способствуют использованию и переиспользованию пользователями ненадежных паролей. Организациям рекомендуется отказаться от подобной практики (см. NIST 800-63) и внедрить многофакторную аутентификацию.

**Сценарий #3:** Тайм-ауты сессий настроены некорректно. Люди используют общедоступные компьютеры для доступа к приложению, а вместо "выхода из приложения" просто закрывают вкладку и уходят. Злоумышленник может открыть тот же самый браузер спустя час и воспользоваться все еще действующей аутентификацией пользователя.

## References

-   [OWASP Proactive Controls: Implement Digital
    Identity](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity)

-   [OWASP Application Security Verification Standard: V2
    authentication](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Application Security Verification Standard: V3 Session
    Management](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Identity](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-Identity_Management_Testing/README), [Authentication](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/README)

-   [OWASP Cheat Sheet:
    Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Credential Stuffing](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Forgot
    Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

-   [OWASP Automated Threats
    Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   NIST 800-63b: 5.1.1 Memorized Secrets

## List of Mapped CWEs

[CWE-255 Credentials Management Errors](https://cwe.mitre.org/data/definitions/255.html)

[CWE-259 Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

[CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

[CWE-288 Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)

[CWE-290 Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)

[CWE-294 Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)

[CWE-295 Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

[CWE-297 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

[CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)

[CWE-302 Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)

[CWE-304 Missing Critical Step in Authentication](https://cwe.mitre.org/data/definitions/304.html)

[CWE-306 Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

[CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

[CWE-346 Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)

[CWE-384 Session Fixation](https://cwe.mitre.org/data/definitions/384.html)

[CWE-521 Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

[CWE-613 Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)

[CWE-620 Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)

[CWE-640 Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)

[CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

[CWE-940 Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html)

[CWE-1216 Lockout Mechanism Errors](https://cwe.mitre.org/data/definitions/1216.html)
