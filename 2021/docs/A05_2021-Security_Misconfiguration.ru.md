# A05:2021 – Некорректная настройка параметров безопасности    ![icon](assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
| :---------: | :----------------: | :----------------: | :------------------: | :-----------------: | :----------: | :----------: | :---------------: | :--------: |
|     20      |       19.84%       |       4.51%        |         8.12         |        6.56         |    89.58%    |    44.84%    |      208,387      |    789     |

## Overview

Moving up from #6 in the previous edition, 90% of applications were
tested for some form of misconfiguration, with an average incidence rate of 4.%, and over 208k occurences of a Common Weakness Enumeration (CWE) in this risk category. With more shifts into highly configurable software, it's not surprising to see this category move up.
Notable CWEs included are *CWE-16 Configuration* and *CWE-611 Improper
Restriction of XML External Entity Reference*.

## Описание 

Приложение уязвимо, если:

-   Любой из компонентов приложения недостаточно защищен или
разрешения облачных сервисов некорректно настроены;.

-   Включены или присутствуют лишние функции (например, неиспользуемые порты, службы, страницы, учетные записи или привилегии).

-   Учетные записи и пароли, создаваемые по умолчанию, используются без изменений.

-   Обработка ошибок позволяет осуществить трассировку стека или получить слишком подробные сообщения об ошибках.

-   Отключены или некорректно настроены последние обновления безопасности.

-   Не выбраны безопасные значения параметров защиты серверов приложений, фреймворков (например, Struts, Spring, ASP.NET), библиотек и т. п.

-   Сервер не использует безопасные заголовки или директивы, а также если они некорректно настроены.

-   ПО устарело или имеет уязвимости (см [A06:2021-Vulnerable
    and Outdated Components](A06_2021-Vulnerable_and_Outdated_Components.md)).

Без организованной и регулярно выполняемой проверки безопасности приложений системы подвержены большему риску.

## Как предотвратить

Необходимо реализовать процесс безопасной установки, включая:

-   Воспроизводимость процессов для быстрого создания безопасных, изолированных сред. Среды для разработки, контроля качества и эксплуатации должны быть настроены одинаково, но иметь разные учетные данные. Процессы должны быть автоматизированы для минимизации затрат на создание новых безопасных сред.

-   Использование платформ только с необходимым набором функций, компонентов, документации и образцов. Удалите или не устанавливайте лишние компоненты или фреймворки.

-   Проверку и актуализацию параметров настройки безопасности в соответствии с выпускаемыми бюллетенями, обновлениями и исправлениями (см. [A06:2021-Vulnerable and Outdated Components](A06_2021-Vulnerable_and_Outdated_Components.md)), а также проверку разрешений облачных хранилищ (например, для контейнеров S3).

-   Создание сегментированной архитектуры приложения, обеспечивающей эффективное разграничение компонентов или клиентов с помощью контейнеризации или облачных групп безопасности (ACL).

-   Использование безопасных директив для клиентов, например Безопасных заголовков.

-   Автоматизацию проверки эффективности используемых конфигураций и настроек во всех средах.

## Примеры сценариев атак

**Сценарий #1:** Сервер приложений поставляется с образцами приложений, которые не удаляются с рабочего сервера. Эти приложения содержат известные уязвимости, позволяющие злоумышленникам скомпрометировать сервер. Если одно из этих приложений является консолью администратора, а стандартные учетные записи не менялись, то атакующий может войти в приложение и перехватить контроль над ним, используя стандартный пароль.

**Сценарий #2:** На сервере не отключен вывод списка файлов в каталогах, что позволяет злоумышленнику найти и выгрузить скомпилированные Java- классы, после декомпиляции и обратного анализа которых можно просмотреть исходный код. В результате атакующий может обнаружить уязвимости и получить доступ к приложению.

**Сценарий #3:** Сервер приложений настроен на отправку подробных сообщений об ошибках, включая данные о трассировке стека. Это может привести к разглашению важной информации, например о версии компонента, содержащей известные уязвимости.

**Сценарий #4:** Поставщик облачных услуг использует стандартные разрешения общего доступа через интернет для других пользователей облака. Это позволяет получить доступ к конфиденциальной информации, доступной в облачном хранилище.

## References

-   [OWASP Testing Guide: Configuration
    Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)

-   [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

-   Application Security Verification Standard V19 Configuration

-   [NIST Guide to General Server
    Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)

-   [CIS Security Configuration
    Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

-   [Amazon S3 Bucket Discovery and
    Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)

## List of Mapped CWEs

[CWE-2 7PK - Environment](https://cwe.mitre.org/data/definitions/2.html)

[CWE-11 ASP.NET Misconfiguration: Creating Debug Binary](https://cwe.mitre.org/data/definitions/11.html)

[CWE-13 ASP.NET Misconfiguration: Password in Configuration File](https://cwe.mitre.org/data/definitions/13.html)

[CWE-15 External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)

[CWE-16 Configuration](https://cwe.mitre.org/data/definitions/16.html)

[CWE-260 Password in Configuration File](https://cwe.mitre.org/data/definitions/260.html)

[CWE-315 Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)

[CWE-520 .NET Misconfiguration: Use of Impersonation](https://cwe.mitre.org/data/definitions/520.html)

[CWE-526 Exposure of Sensitive Information Through Environmental Variables](https://cwe.mitre.org/data/definitions/526.html)

[CWE-537 Java Runtime Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/537.html)

[CWE-541 Inclusion of Sensitive Information in an Include File](https://cwe.mitre.org/data/definitions/541.html)

[CWE-547 Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)

[CWE-611 Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

[CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)

[CWE-756 Missing Custom Error Page](https://cwe.mitre.org/data/definitions/756.html)

[CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)

[CWE-942 Overly Permissive Cross-domain Whitelist](https://cwe.mitre.org/data/definitions/942.html)

[CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

[CWE-1032 OWASP Top Ten 2017 Category A6 - Security Misconfiguration](https://cwe.mitre.org/data/definitions/1032.html)

[CWE-1174 ASP.NET Misconfiguration: Improper Model Validation](https://cwe.mitre.org/data/definitions/1174.html)
