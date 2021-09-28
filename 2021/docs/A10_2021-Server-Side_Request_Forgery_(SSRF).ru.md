# A10:2021 – Подделка запросов на стороне сервера (SSRF)    ![icon](assets/TOP_10_Icons_Final_SSRF.png){: style="height:80px;width:80px" align="right"}

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
| :---------: | :----------------: | :----------------: | :------------------: | :-----------------: | :----------: | :----------: | :---------------: | :--------: |
|      1      |       2.72%        |       2.72%        |         8.28         |        6.72         |    67.72%    |    67.72%    |       9,503       |    385     |

## Overview

This category is added from the Top 10 community survey (#1). The data shows a
relatively low incidence rate with above average testing coverage and
above-average Exploit and Impact potential ratings. As new entries are
likely to be a single or small cluster of Common Weakness Enumerations (CWEs)
for attention and
awareness, the hope is that they are subject to focus and can be rolled
into a larger category in a future edition.

## Description 

Слабые для SSRF места появляются, когда веб-приложение получает удаленный ресурс, не проверяя URL, введенный пользователем. Это позволяет злоумышленнику вынудить приложение отправить созданный запрос по непредусмотренному адресу, даже когда имеется защита фаервола, VPN или других видов управления сетевым доступом.

Так как современные веб-приложения предоставляют конечным пользователям удобные функции, получение данных по URL становится общепринятым сценарием. Как результат, частота применения SSRF возрастает. Также из-за облачных сервисов и сложности архитектур опасность SSRF становится все выше.

## Как предотвратить

Разработчики могут предотвратить SSRF, реализовав все или некоторые механизмы защиты:

### **Из сетевого слоя**

-   Разделите функциональность удаленного доступа к ресурсам на отдельные сети, чтобы уменьшить воздействие SSRF.

-   Настройте политики фаервола или правила механизма управления доступа к сети на "отказ по умолчанию", чтобы заблокировать весь внутрисетевой трафик, кроме необходимого.<br/> 
    *Подсказки:*<br> 
    ~ Настройте владение и жизенный цикл для правил фаервола с привязкой к приложениям.<br/>
    ~ Журналируйте все принятые *и* заблокированные сетевые потоки в фаерволах (см. [A09:2021-Security Logging and Monitoring Failures](A09_2021-Security_Logging_and_Monitoring_Failures.md)).
    
### **Из слоя приложения:**

-   Чистите и проверяйте все данные, вводимые пользователем.

-   Ограничьте набор возможных URL-схем, портов и адресов при помощи белого списка.

-   Не отправляйте сырые ответы клиентам.

-   Отключите перенаправление HTTP.

-   Проверяйте соответствие URL, чтобы избежать таких атак, как перепривязка DNS и условия гонки "time of check, time of use" (TOCTOU).

Не пытайтесь уменьшить вероятность SSRF, используя список запретов или регулярные выражения. У злоумышлеников есть списки данных наполнения, инструменты и навыки обхода списков запретов.

### **Дополнительные меры:**

-   Не развертывайте другие сервисы безопасности на фронт-системах (например, OpenID). Контролируйте локальный трафик в этих системах (например, localhost).

-   Для фронт-эндов с управляемыми пользовательскими группами используйте сетевое шифрование (например, VPN) на независимых системах, чтобы удовлетворить высокие требования защиты.


## Example Attack Scenarios

Attackers can use SSRF to attack systems protected behind web
application firewalls, firewalls, or network ACLs, using scenarios such
as:

**Scenario #1:** Port scan internal servers – If the network architecture
is unsegmented, attackers can map out internal networks and determine if
ports are open or closed on internal servers from connection results or
elapsed time to connect or reject SSRF payload connections.

**Scenario #2:** Sensitive data exposure – Attackers can access local 
files such as or internal services to gain sensitive information such
as `file:///etc/passwd</span>` and `http://localhost:28017/`.

**Scenario #3:** Access metadata storage of cloud services – Most cloud
providers have metadata storage such as `http://169.254.169.254/`. An
attacker can read the metadata to gain sensitive information.

**Scenario #4:** Compromise internal services – The attacker can abuse
internal services to conduct further attacks such as Remote Code
Execution (RCE) or Denial of Service (DoS).

## References

-   [OWASP - Server-Side Request Forgery Prevention Cheat
    Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

-   [PortSwigger - Server-side request forgery
    (SSRF)](https://portswigger.net/web-security/ssrf)

-   [Acunetix - What is Server-Side Request Forgery
    (SSRF)?](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/)

-   [SSRF
    bible](https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf)

-   [A New Era of SSRF - Exploiting URL Parser in Trending Programming
    Languages!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

## List of Mapped CWEs

[CWE-918 Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
