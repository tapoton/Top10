# A08:2021 – Software and Data Integrity Failures    ![icon](assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
| :---------: | :----------------: | :----------------: | :------------------: | :-----------------: | :----------: | :----------: | :---------------: | :--------: |
|     10      |       16.67%       |       2.05%        |         6.94         |        7.94         |    75.04%    |    45.35%    |      47,972       |   1,152    |

## Overview

A new category for 2021 focuses on making assumptions related to
software updates, critical data, and CI/CD pipelines without verifying
integrity. One of the highest weighted impacts from 
Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS) 
data. Notable Common Weakness Enumerations (CWEs) include
*CWE-829: Inclusion of Functionality from Untrusted Control Sphere*,
*CWE-494: Download of Code Without Integrity Check*, and 
*CWE-502: Deserialization of Untrusted Data*.

## Описание 

Недостатки обеспечения целостности ПО и данных относятся к коду и инфраструктуре, которые не защищены против нарушений целостности. Примером является ситуация, когда приложение полагается на плагины, библиотеки или модули из недоверенных источников, репозиториев и сети доставки контента (CDN). Небезопасные сервисы непрерывной интеграции и доставки могут создавать возможность неавторизованного доступа, вредоносного кода или компрометации системы. Напоследок, многие приложения содержат функциональность автоматического обновления, когда обновления скачиваются без достаточной проверки целостности и применятся к предыдущим доверенным версиям. Потенциально злоумышленники могут загрузить собственные обновления. Другой пример – когда объекты или данные сериализуются в структуру, которую злоумышленник может видеть и изменять, система становится уязвимой для небезопасной десериализации.

## Как предотвратить

-   Используйте цифровые подписи или сходные механизмы проверки, что ПО или данные получены из доверенных источников и не были подменены.

-   Проверяйте, что библиотеки и зависимости, такие как npm или Maven, скачивают доверенные репозитории. Если у вас более высокий уровень риска, рассмотрите создание внутреннего проверенного репозитория.

-   Убедитесь, что для проверки компонентов на уязвимости используются инструменты безопасности поставщиков ПО, такие как OWASP Dependency Check или OWASP CycloneDX.

-   Для уменьшения шанса появления вредоносного кода или конфигурации в вашем конвейере убедитесь, что существует процесс проверки кода и изменений конфигурации.

-   Убедитесь, что ваш конвейер непрерывной интеграции и доставки имеет правильное разделение, конфигурацию и контроль доступа, чтобы гарантировать целостность кода, проходящего через процесс сборки и развертывания.

-   Убедитесь, что неподписанные и незашифрованные данные не отправляются непроверенным клиентам без какой-либо проверки целотстности или цифровой подписи, чтобы обнаружись взлом или повторение сериализованных данных.

## Примеры сценариев атак

**Сценарий #1 Изменение без подписи:** Многие домашние маршрутизаторы, ТВ-приставки, программное обеспечение устройств и прочее не проверяют обновления при помощи специального ПО. Неподписанное ПО все чаще становится целью злоумышленников и ситуация становится только хуже. Это вопрос, требующий решения, так как нет другого способа устранить эту проблему, кроме исправить следующую версию и ждать, когда предыдущие версии перестанут использоваться. 

**Сценарий  #2 Вредоносное обновление SolarWinds**:  Nation-states have been
known to attack update mechanisms, with a recent notable attack being
the SolarWinds Orion attack. The company that develops the software had
secure build and update integrity processes. Still, these were able to
be subverted, and for several months, the firm distributed a highly
targeted malicious update to more than 18,000 organizations, of which
around 100 or so were affected. This is one of the most far-reaching and
most significant breaches of this nature in history.

**Сценарий  #3 Insecure Deserialization:** A React application calls a
set of Spring Boot microservices. Being functional programmers, they
tried to ensure that their code is immutable. The solution they came up
with is serializing the user state and passing it back and forth with
each request. An attacker notices the "rO0" Java object signature (in base64) and
uses the Java Serial Killer tool to gain remote code execution on the
application server.

## References

-   \[OWASP Cheat Sheet: Software Supply Chain Security\](Coming Soon)

-   \[OWASP Cheat Sheet: Secure build and deployment\](Coming Soon)

-    [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html) 
 
-   [OWASP Cheat Sheet: Deserialization](
    <https://www.owasp.org/index.php/Deserialization_Cheat_Sheet>)

-   [SAFECode Software Integrity Controls](
    https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)

-   [A 'Worst Nightmare' Cyberattack: The Untold Story Of The
    SolarWinds
    Hack](<https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack>)

-   [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)

-   [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)

## List of Mapped CWEs

[CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

[CWE-353 Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)

[CWE-426 Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)

[CWE-494 Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)

[CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

[CWE-565 Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)

[CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision](https://cwe.mitre.org/data/definitions/784.html)

[CWE-829 Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

[CWE-830 Inclusion of Web Functionality from an Untrusted Source](https://cwe.mitre.org/data/definitions/830.html)

[CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
