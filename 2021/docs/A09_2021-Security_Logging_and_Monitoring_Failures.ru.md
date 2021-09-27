# A09:2021 – Security Logging and Monitoring Failures    ![icon](assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
| :---------: | :----------------: | :----------------: | :------------------: | :-----------------: | :----------: | :----------: | :---------------: | :--------: |
|      4      |       19.23%       |       6.51%        |         6.87         |        4.99         |    53.67%    |    39.97%    |      53,615       |    242     |

## Overview

Security logging and monitoring came from the Top 10 community survey (#3), up
slightly from the tenth position in the OWASP Top 10 2017. Logging and
monitoring can be challenging to test, often involving interviews or
asking if attacks were detected during a penetration test. There isn't
much CVE/CVSS data for this category, but detecting and responding to
breaches is critical. Still, it can be very impactful for accountability, visibility,
incident alerting, and forensics. This category expands beyond *CWE-778
Insufficient Logging* to include *CWE-117 Improper Output Neutralization
for Logs*, *CWE-223 Omission of Security-relevant Information*, and
*CWE-532* *Insertion of Sensitive Information into Log File*.

## Description 

Возвращаясь в OWASP Top 10 2021, эта категория призвана помочь обнаружить, эскалировать и ответить на существующие бреши. Без журналирования и мониторинга бреши невозможно обнаружить. Недостатки журналирования, обнаружения атак, мониторинга и реагирования на инциденты выявляются постоянно:

-   подвергаемые аудиту события, такие как удачные и неудачные попытки входа в систему, а также важные транзакции, не регистрируются.

-   предупреждения и ошибки не регистрируются или регистрируются некорректно.

-   журналы приложений и API не проверяются на предмет подозрительной активности.

-   журналы хранятся только локально.

-   пороговые значения предупреждений и схемы реагирования на инциденты отсутствуют или являются неэффективными.

-   тестирование на проникновение и сканирование инструментами DAST (например, OWASP ZAP) не выдают предупреждений.

-   приложение не может определять, реагировать или предупреждать об атаках в реальном или почти реальном времени.

В системе имеется утечка данных, если журналы регистрации и предупреждения доступны пользователям или атакующим (см. [A01:2021-Broken Access Control](A01_2021-Broken_Access_Control.md)).

## Как предотвратить

Исходя из значимости данных, хранимых или обрабатываемых приложением, необходимо:

-   регистрировать все ошибки входа, доступа и проверки данных на стороне сервера с указанием контекста, достаточного для выявления подозрительных или вредоносных действий, а также хранить их для последующего анализа.

-   регистрировать события в формате, наиболее подходящем для обработки централизованной службой журналирования.

-   Ensure log data is encoded correctly to prevent injections or
    attacks on the logging or monitoring systems.

-   использовать контроль целостности журналов аудита важных транзакций для предотвращения подмены или удаления данных, например с помощью доступных только для добавления таблиц БД.

-   команды DevSecOps должны использовать эффективные системы мониторинга и предупреждения для своевременного обнаружения подозрительных действий и реагирования на них.

-   разработать или утвердить руководство по реагированию на инциденты и устранению их последствий, такое как NIST 800-61 rev2 или новее.

Существуют коммерческие и бесплатные системы защиты приложений (например, OWASP ModSecurity Core Rule Set), а также программы корреляции журналов с настраиваемыми панелями и предупреждениями (например, Elasticsearch, Logstash, Kibana (ELK) stack).

## Example Attack Scenarios

**Scenario #1:** A childrens' health plan provider's website operator
couldn't detect a breach due to a lack of monitoring and logging. An
external party informed the health plan provider that an attacker had
accessed and modified thousands of sensitive health records of more than
3.5 million children. A post-incident review found that the website
developers had not addressed significant vulnerabilities. As there was
no logging or monitoring of the system, the data breach could have been
in progress since 2013, a period of more than seven years.

**Scenario #2:** A major Indian airline had a data breach involving more
than ten years' worth of personal data of millions of passengers,
including passport and credit card data. The data breach occurred at a
third-party cloud hosting provider, who notified the airline of the
breach after some time.

**Scenario #3:** A major European airline suffered a GDPR reportable
breach. The breach was reportedly caused by payment application security
vulnerabilities exploited by attackers, who harvested more than 400,000
customer payment records. The airline was fined 20 million pounds as a
result by the privacy regulator.

## References

-   [OWASP Proactive Controls: Implement Logging and
    Monitoring](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging.html)

-   [OWASP Application Security Verification Standard: V8 Logging and
    Monitoring](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Testing for Detailed Error
    Code](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code)

-   [OWASP Cheat Sheet:
    Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

-   [OWASP Cheat Sheet:
    Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html))   

-   [Data Integrity: Recovering from Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Data Integrity: Identifying and Protecting Assets Against
    Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Data Integrity: Detecting and Responding to Ransomware and Other
    Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

## List of Mapped CWEs

[CWE-117 Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)

[CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)

[CWE-532 Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

[CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
