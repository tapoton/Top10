# A03:2021 – Injection    ![icon](assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"} 

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
| :---------: | :----------------: | :----------------: | :------------------: | :-----------------: | :----------: | :----------: | :---------------: | :--------: |
|     33      |       19.09%       |       3.37%        |         7.25         |        7.15         |    94.04%    |    47.90%    |      274,228      |   32,078   |

## Обзор

Injection slides down to the third position. 94% of the applications
were tested for some form of injection with a max incidence rate of 19%, an average incidence rate of 3%, and 274k occurances. Notable Common Weakness Enumerations (CWEs) included are
*CWE-79: Cross-site Scripting*, *CWE-89: SQL Injection*, and *CWE-73:
External Control of File Name or Path*.

## Описание 

Приложение уязвимо к атакам, когда:

-   Вводимые пользователем данные не проверяются, не фильтруются
или не очищаются.

-   Динамические запросы или непараметризованные вызовы без контекстного экранирования напрямую используются в интерпретаторе.

-   Вредоносные данные используются в поисковых параметрах объектно-реляционного отображения для извлечения дополнительной или критически важной информации.

-   Вредоносные данные используются или добавляются таким образом, что SQL- код или команды содержат структурные и вредоносные данные в динамических запросах, командах или хранимых процедурах.

Наиболее распространенными являются SQL-, NoSQL-, ORM-, LDAP-, EL- или OGNL-внедрения, а также внедрения команд ОС. То же самое касается всех интерпретаторов. Анализ исходного кода является лучшим способом обнаружения внедрений, за которым следует полное автоматизированное тестирование всех вводимых параметров, заголовков, URL, куки, JSON-, SOAP- и XML-данных. Организации также могут включать в процесс непрерывной интеграции и развертывания ПО (CI/CD) статическое (SAST) и динамическое (DAST) тестирование кода и приложений для обнаружения новых уязвимостей перед внедрением приложений в производство.

## Как предотвратить

Для предотвращения внедрений необходимо изолировать данные от команд и запросов:

-   Используйте безопасный API, исключающий применение интерпретатора или предоставляющий параметризованный интерфейс, либо используйте инструменты объектно-реляционного отображения (ORM).<br/>
    **Примечание:** даже параметризованные хранимые процедуры могут привести к SQL-внедрениям, если PL/SQL или T-SQL позволяют присоединять запросы и данные или выполнять вредоносный код с помощью EXECUTE IMMEDIATE или exec().

-   Реализуйте на сервере белые списки для проверки входных данных. Это, конечно, не обеспечит полную защиту, поскольку многие приложения используют спецсимволы, например, в текстовых областях или API для мобильных приложений.

-   Для остальных динамических запросов реализуйте экранирование спецсимволов, используя соответствующий интерпретатору синтаксис.<br/>
    **Примечание:** элементы SQL-структуры, такие как названия таблиц или столбцов, нельзя экранировать, поэтому предоставляемые пользователями названия представляют опасность. Это обычная проблема программ для составления отчетов.

-   Используйте в запросах LIMIT или другие элементы управления SQL для предотвращения утечек данных.

## Примеры сценариев атак

**Сценарий #1:** Приложение использует недоверенные данные при создании следующего уязвимого SQL-вызова:
```
String query = "SELECT \* FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

**Сценарий #2:** Безоговорочное доверие приложений к фреймворкам может привести к появлению уязвимых запросов (например, в языке запросов HQL):
```
 Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

В обоих случаях злоумышленник изменяет в своем браузере значение параметра `"id"` для отправки `' or '1'='1`. Например:
```
 http://example.com/app/accountView?id=' or '1'='1
```

Изменение обоих запросов позволяет получить все записи из таблицы учетных данных. Более серьезные атаки позволяют изменить или удалить данные, а также вызвать хранимые процедуры.

## References

-   [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)

-   [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: SQL Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection),
    and [ORM Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)

-   [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)

-   [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)

-   [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)

## List of Mapped CWEs

[CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

[CWE-74 Improper Neutralization of Special Elements in Output Used by a
Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)

[CWE-75 Failure to Sanitize Special Elements into a Different Plane
(Special Element Injection)](https://cwe.mitre.org/data/definitions/75.html)

[CWE-77 Improper Neutralization of Special Elements used in a Command
('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)

[CWE-78 Improper Neutralization of Special Elements used in an OS Command
('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

[CWE-79 Improper Neutralization of Input During Web Page Generation
('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

[CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page
(Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)

[CWE-83 Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html)

[CWE-87 Improper Neutralization of Alternate XSS Syntax](https://cwe.mitre.org/data/definitions/87.html)

[CWE-88 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)

[CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)

[CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)

[CWE-91 XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)

[CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)

[CWE-94 Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

[CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

[CWE-96 Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)

[CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)

[CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html)

[CWE-99 Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)

[CWE-100 Deprecated: Was catch-all for input validation issues](https://cwe.mitre.org/data/definitions/100.html)

[CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)

[CWE-116 Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)

[CWE-138 Improper Neutralization of Special Elements](https://cwe.mitre.org/data/definitions/138.html)

[CWE-184 Incomplete List of Disallowed Inputs](https://cwe.mitre.org/data/definitions/184.html)

[CWE-470 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')](https://cwe.mitre.org/data/definitions/470.html)

[CWE-471 Modification of Assumed-Immutable Data (MAID)](https://cwe.mitre.org/data/definitions/471.html)

[CWE-564 SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)

[CWE-610 Externally Controlled Reference to a Resource in Another Sphere](https://cwe.mitre.org/data/definitions/610.html)

[CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)

[CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html)

[CWE-652 Improper Neutralization of Data within XQuery Expressions ('XQuery Injection')](https://cwe.mitre.org/data/definitions/652.html)

[CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')] (https://cwe.mitre.org/data/definitions/917.html)
