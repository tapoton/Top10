# A06:2021 – Vulnerable and Outdated Components    ![icon](assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Max Coverage | Avg Coverage | Avg Weighted Exploit | Avg Weighted Impact | Total Occurrences | Total CVEs |
| :---------: | :----------------: | :----------------: | :----------: | :----------: | :------------------: | :-----------------: | :---------------: | :--------: |
|      3      |       27.96%       |       8.77%        |    51.78%    |    22.47%    |         5.00         |        5.00         |      30,457       |     0      |

## Overview

It was #2 from the Top 10 community survey but also had enough data to make the
Top 10 via data. Vulnerable Components are a known issue that we
struggle to test and assess risk and is the only category to not have
any Common Weakness Enumerations (CWEs) mapped to the included CWEs, so a default exploits/impact
weight of 5.0 is used. Notable CWEs included are *CWE-1104: Use of
Unmaintained Third-Party Components* and the two CWEs from Top 10 2013
and 2017.

## Description 

Приложение уязвимо, если:

-   Вы не знаете версии всех используемых (на стороне клиента и на
стороне сервера) компонентов. Сюда относятся сами компоненты и встроенные зависимости.

-   ПО содержит уязвимости, не поддерживается или устарело. Сюда относятся ОС, веб-серверы, серверы приложений, СУБД, приложения, API, а также все компоненты, среды исполнения и библиотеки.

-   Поиск уязвимостей выполняется нерегулярно, а также отсутствует подписка на бюллетени по безопасности используемых компонентов.

-   Своевременно не устанавливаются исправления или обновления для используемых платформ, фреймворков и зависимостей. Обычно такое происходит, когда наличие обновлений проверяется раз в месяц или квартал, в результате чего организации неделями или месяцами не устраняют исправленные уязвимости.

-   Разработчики ПО не тестируют совместимость обновленных или исправленных библиотек.

-   не обеспечивается безопасность компонентов (см. A05:2021-Security Misconfiguration).

## Как предотвратить

Необходимо реализовать процесс управления обновлениями:

-   Удалите неиспользуемые зависимости, а также лишние функции, компоненты, файлы и сведения из документации.

-   Регулярно проверяйте актуальность версий клиентских и серверных компонентов (например, фреймворков и библиотек), а также их зависимостей, используя такие инструменты, как versions, DependencyCheck, retire.js. Следите за новостями об уязвимостях на соответствующих ресурсах, таких как CVE и NVD. Используйте инструменты анализа состава ПО для автоматизации процесса. Подпишитесь на рассылки об уязвимостях, относящихся к используемым вами компонентам.

-   Загружайте компоненты из официальных источников по безопасным ссылкам. Отдавайте предпочтение подписанным пакетам для снижения риска установки измененного или вредоносного компонента (See A08:2021-Software and Data Integrity Failures).

-   Следите за библиотеками и компонентами, которые не поддерживаются или не получают обновлений безопасности. Если обновление невозможно, попробуйте использовать виртуальные патчи для обнаружения или предотвращения эксплуатации известных уязвимостей.

Каждая организация должна обеспечить отслеживание, приоритизацию и применение обновлений или изменений в конфигурации на протяжении всего жизненного цикла приложения или линейки приложений.

## Примеры сценариев атак

**Сценарий #1:** Компоненты обычно запускаются с привилегиями приложения, поэтому уязвимость в любом из компонентов может привести к серьезным последствиям. Уязвимость может появиться случайно (например, из-за ошибки в коде) или преднамеренно (например, бэкдор). Вот несколько примеров эксплуатации уязвимостей, обнаруженных в компонентах:

-   CVE-2017-5638, уязвимость в Struts 2, позволяющая удаленно выполнить произвольный код на сервере, стала причиной нескольких серьезных взломов;

-   Уязвимости в интернете вещей (IoT) зачастую сложно или невозможно устранить, а это может привести к серьезным последствиям (например, в случае биомедицинских приборов).

Существуют автоматизированные инструменты, позволяющие злоумышленникам находить уязвимые или некорректно настроенные системы. Например, поисковик Shodan для IoT позволяет обнаружить устройства, в которых до сих пор не устранена уязвимость Heartbleed, которая была исправлена в апреле 2014 года.

## References

-   OWASP Application Security Verification Standard: V1 Architecture,
    design and threat modelling

-   OWASP Dependency Check (for Java and .NET libraries)

-   OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)

-   OWASP Virtual Patching Best Practices

-   The Unfortunate Reality of Insecure Libraries

-   MITRE Common Vulnerabilities and Exposures (CVE) search

-   National Vulnerability Database (NVD)

-   Retire.js for detecting known vulnerable JavaScript libraries

-   Node Libraries Security Advisories

-   [Ruby Libraries Security Advisory Database and Tools]()

-   https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf

## List of Mapped CWEs

CWE-937 OWASP Top 10 2013: Using Components with Known Vulnerabilities

CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities

CWE-1104 Use of Unmaintained Third Party Components
