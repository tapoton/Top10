# A04:2021 – Insecure Design   ![icon](assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"} 

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
| :---------: | :----------------: | :----------------: | :------------------: | :-----------------: | :----------: | :----------: | :---------------: | :--------: |
|     40      |       24.19%       |       3.00%        |         6.46         |        6.78         |    77.25%    |    42.51%    |      262,407      |   2,691    |

## Overview

A new category for 2021 focuses on risks related to design and architectural flaws, with a call for more use of threat modeling, secure design patterns, and reference architectures. As a community we need to move beyond  "shift-left" in the coding space to pre-code activities that are critical for the principles of Secure by Design. Notable Common Weakness Enumerations (CWEs) include *CWE-209: Generation of Error Message Containing Sensitive Information*, *CWE-256: Unprotected Storage of Credentials*, *CWE-501: Trust Boundary Violation*, and *CWE-522: Insufficiently Protected Credentials*.

## Описание

Небезопасное проектирование – это большая категория, представляющая различные уязвимости, которые можно описать, как "недостаток или неэффектиность проектирования контроля". Небезопасное проетирование не является источником всех остальных категорий рисков из Top 10. Есть разница между небезопасным проектированием и небезопасной реализацией. Мы проводим черту между ошибками проектирования и дефектами реализации, поскольку у них разные причины возникновения и способы устранения. Даже при безопасном проектировании возможны дефекты реализации, приводящие к уязвимостям, которые могут быть использованы для взлома. Однако, ошибки небезопасного проектирования нельзя исправить идеальной реализацией, так как инструменты, нужные для защиты от некоторых атак, могли быть не созданы. Одним из факторов, дополняющих небезопасное проектирование, является недостаток моделирования бизнес-рисков, присущих разрабатываемому ПО или системе, и, таким образом, невозможность определить какой уровень безопасного проектирования требуется.

### Требования и управление ресурсами

Необходимо собирать и обсуждать с бизнесом бизнес-требования, включая требования конфиденциальности, целостности, доступности и подлинности всех наборов данных и ожидаемой бизнес-логики. Нужно брать в расчет, насколько проектируемое приложение будет доступным извне и необходимо ли разделение арендаторов (tenants) в дополнение к контролю доступа. Соберите технические требования, включая функциональные и нефункциональные требования безопасности. Спланируйте и обсудите бюджет на проектирование, реализацию, тестирование и интеграцию процессов, включая деятельность, связанную с безопасностью.

### Безопасное проектирование

Безопасное проектирование – это культура и методология, при которой постоянно оцениваются угрозы и проверяется, что программный код продуманно спроектирован и протестирован, так чтобы предотвращать известные атаки. Моделирование угрозы должно быть интегрировано в сессии по доработке (или сходного рода активности); необходимо отыскивать изменения в потоках данных и контроле доступа или других инструментах безопасности. При разработке пользовательских историй необходимо определять корректные состояния успеха и ошибки, и проверять, что все эти состояния понятны и согласованы со всеми участниками процесса. Анализируйте исходные предположения и условия на наличие ожидаемых состояний и состояний ошибки, проверяйте что все эти состояния соответствуют ожиданиям. Определите, как именно проверять предположения, и соблюдать необходимые условия для корректного поведения приложения. Проверяйте, что результаты задокументированы в пользовательской истории. Учитесь на ошибках и предлагайте позитивное поощрение, чтобы продвигать улучшения. Безопасное проектирование это и не дополнение, и не инструмент, который можно просто добавить к вашему ПО.

### Жизненный цикл безопасного проектирования

Защищенное программное обеспечения требует наличия жизненного цикла безопасной разработки, в некотором роде шаблона безопасного проектирования, оформленной методологии, библиотеки безопасных компонентов, инструментария и моделирования угроз. Обращайтесь к вашим специалистам по безопасности в начале проекта, а также во время разработки и поддержки проекта. Применяйте [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org), чтобы правильно организовать усилия по безопасной разработке.

## Как предотвратить

-   Чтобы спроектировать и создать инструменты обеспечения безопасности и конфиденциальности, разработайте и ипользуйте жизненный цикл безопасной разработки вместе с профессионалами по безопасности приложений.

-   Разработайте и используйте библиотеку шаблонов безопасного проектирования и готовых к использованию компонентов.

-   Используйте моделирование угроз для реализации критической аутентификации, контроля доступа, бизнес-логики и передачи ключей.

-   Внедрите язык и инструменты безопасности в пользовательские истории

-   Внедрите проверки в каждом слое вашего приложения (от фронтэнда до бэкэнда)

-   Пишите юнит- и интеграционные тесты, чтобы проверять, что все критичные сценарии невосприимчивы к моделям угроз. Соберите сценарии корректного и некорректного использования для каждого слоя вашего приложения.

-   Выделите слои системы и сетевые слои в зависимости от их открытости и необходимости защиты.

-   Segregate tenants robustly by design throughout all tiers

-   Ограничьте доступ к ресурсам для пользователей и сервисов

## Example Attack Scenarios

**Сценарий #1:** Восстановление пароля может включать "вопросы и ответы", что запрещено NIST 800-63b, OWASP ASVS и OWASP Top 10. Вопросы и ответы не могут доказывать подлинность, так как несколько людей могут знать ответ, поэтому они запрещены. Такая реализация должна быть удалена и заменена более безопасными подходами.

**Сценарий #2:** Сеть кинотеатров предоставляет скидку на групповое бронирование и позволяет бронировать места без депозита до 15 человек. Злоумышленники могут попробовать забронировать 600 мест во всех кинотеатрах в несколько запросов, что повлечет большие потери.

**Сценарий #3:** Веб-сайт торговой сети не защищен против ботов, которых запускают перекупщики, чтобы купить дорогие видео-карты и перепродать их на аукционе. Из-за этого производители видео-карт и владельцы торговых сетей получают плохую репутацию, а покупатели не могут купить карты ни за какие деньги. Правильное проектирование анти-бота и правила доменной логики, могут вычислить неаутентифицированные покупки и отклонять такие транзакции.

## References

-   [OWASP Cheat Sheet: Secure Design Principles](Coming Soon)

-   [OWASP SAMM: Design:Security Architecture](https://owaspsamm.org/model/design/security-architecture/)

-   [OWASP SAMM: Design:Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/) 

-   [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/system/files/documents/2021/07/13/Developer%20Verification%20of%20Software.pdf)

-   [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org)

-   [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)

## List of Mapped CWEs

[CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)

[CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)

[CWE-209 Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)

[CWE-213 Exposure of Sensitive Information Due to Incompatible Policies](https://cwe.mitre.org/data/definitions/213.html)

[CWE-235 Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)

[CWE-256 Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)

[CWE-257 Storing Passwords in a Recoverable Format](https://cwe.mitre.org/data/definitions/257.html)

[CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)

[CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

[CWE-280 Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html)

[CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

[CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

[CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)

[CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)

[CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)

[CWE-430 Deployment of Wrong Handler](https://cwe.mitre.org/data/definitions/430.html)

[CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)

[CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html)

[CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)

[CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)

[CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)

[CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)

[CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)

[CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)

[CWE-579 J2EE Bad Practices: Non-serializable Object Stored in Session](https://cwe.mitre.org/data/definitions/579.html)

[CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)

[CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)

[CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)

[CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)

[CWE-650 Trusting HTTP Permission Methods on the Server Side](https://cwe.mitre.org/data/definitions/650.html)

[CWE-653 Insufficient Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)

[CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)

[CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)

[CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)

[CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)

[CWE-840 Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)

[CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)

[CWE-927 Use of Implicit Intent for Sensitive Communication](https://cwe.mitre.org/data/definitions/927.html)

[CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)

[CWE-1173 Improper Use of Validation Framework](https://cwe.mitre.org/data/definitions/1173.html)
