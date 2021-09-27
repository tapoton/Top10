# A01:2021 – Недостатки Контроля Доступа    ![icon](assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}

## Factors

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
| :---------: | :----------------: | :----------------: | :------------------: | :-----------------: | :----------: | :----------: | :---------------: | :--------: |
|     34      |       55.97%       |       3.81%        |         6.92         |        5.93         |    94.55%    |    47.72%    |      318,487      |   19,013   |

## Обзор

Moving up from the fifth position, 94% of applications were tested for
some form of broken access control with the average incidence rate of 3.81%, and has the most occurrences in the contributed dataset with over 318k. Notable Common Weakness Enumerations (CWEs) included are *CWE-200: Exposure of Sensitive Information to an Unauthorized Actor*, *CWE-201:
Exposure of Sensitive Information Through Sent Data*, and *CWE-352:
Cross-Site Request Forgery*.

## Description

Контроль доступа предполагает наличие политики, определяющей права пользователей. Обход ограничений доступа обычно приводит к несанкционированному разглашению, изменению или уничтожению данных, а также выполнению непредусмотренных полномочиями бизнес-функций. Наиболее распространенные уязвимости контроля доступа включают: 

-   Нарушение принципа наименьших привелений или запрета по умолчанию, когда доступ должен даваться только на определенные действия, определенным ролям или пользователям, но его его может получить каждый.

-   Обход ограничений доступа путем изменения URL, внутреннего состояния приложения или HTML-страницы, а также с помощью специально разработанных API.

-   Возможность изменения первичного ключа для доступа к записям других пользователей, включая просмотр или редактирование чужой учетной записи.

-   Доступ к API с отсутствующим контролем доступа для POST, PUT и DELETE запросов.

-   Повышение привелегий. Выполнение операций с правами пользователя, не входя в систему, или с правами администратора, войдя в систему с правами пользователя.

-   Манипуляции с метаданными, например повторное воспроизведение или подмена токенов контроля доступа JWT или куки-файлов, а также изменение скрытых полей для повышения привилегий или некорректное аннулирование JWT.

-   Несанкционированный доступ к API из-за некорректной настройки междоменного использования ресурсов (CORS).

-   Доступ неаутентифицированных пользователей к страницам, требующим аутентификации, или доступ непривилегированных пользователей к привилегированным страницам. Доступ к API с отсутствующим контролем привилегий для POST-, PUT- и DELETE-методов/запросов.

## Как предотвратить

Контроль доступа эффективен только при реализации через проверенный код на стороне сервера или беcсерверный API, где атакующий не может изменять проверки прав доступа или метаданные. Рекомендуется:

-   Запрещать доступ по умолчанию, за исключением открытых ресурсов.

-   Реализовать механизмы контроля доступа и использовать их во всех приложениях, а также минимизировать междоменное использование ресурсов.

-   Контролировать доступ к моделям, используя владение записями, а не возможность пользователей создавать, просматривать, обновлять или удалять любые записи.

-   Использовать модели доменов для реализации специальных ограничений, относящихся к приложениям.

-   Отключить вывод списка каталогов веб-сервера, а также обеспечить отсутствие метаданных файлов (например, .git) и файлов резервных копий в корневых веб-каталогах.

-   Регистрировать сбои контроля доступа и уведомлять администраторов при необходимости (например, если сбои повторяются).

-   Ограничивать частоту доступа к API и контроллерам для минимизации ущерба от инструментов автоматизации атак.

-   Для сессий с сохранением состояния после выхода пользователя из системы аннулировать идентификатор сессии. Для сессий без сохранения состояния JWT-токены должны быть короткоживущими, чтобы сделать минимальным временной промежуток, за который злоумышленник сможет атаковать. Для JWT с долгим периодом жизни рекомендуется отзывать доступ согласно стандартам OAuth.

Разработчики и тестировщики должны добавлять сценарии unit и интеграционного тестирования для проверки контроля доступа.

## Примеры сценариев атак

**Сценарий #1:** Приложение использует непроверенные данные в SQL запросе, который получает доступ к информации учетной записи:

```
 pstmt.setString(1, request.getParameter("acct"));
 ResultSet results = pstmt.executeQuery( );
```

Злоумышленник просто изменяет параметр 'acct', чтобы получить данные о той учетной записи, которая ему нужна. Если нужная проверка не будет выполнена, злоумышленик может получить доступ к учетной записи любого пользователя.

```
 https://example.com/app/accountInfo?acct=notmyacct
```

**Сценарий #2:** Злоумышленник просто перебирает параметры для нужного URL. Для доступа к странице администратора нужны права администратора.

```
 https://example.com/app/getappInfo
 https://example.com/app/admin_getappInfo
```

Если неаутентифицированный пользователь может получить доступ к любой странице, это слабое место. Если пользователь, не являющийся администратором может получить доступ к странице администратора, это также слабое место.

## Ссылки

-   [OWASP Proactive Controls: Enforce Access
    Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

-   [OWASP Application Security Verification Standard: V4 Access
    Control](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Authorization
    Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

-   [OWASP Cheat Sheet: Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

-   [PortSwigger: Exploiting CORS
    misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
    
-   [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)

## List of Mapped CWEs

[CWE-22 Improper Limitation of a Pathname to a Restricted Directory
('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

[CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)

[CWE-35 Path Traversal: '.../...//'](https://cwe.mitre.org/data/definitions/35.html)

[CWE-59 Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)

[CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

[CWE-201 Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html)

[CWE-219 Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html)

[CWE-264 Permissions, Privileges, and Access Controls (should no longer be used)](https://cwe.mitre.org/data/definitions/264.html)

[CWE-275 Permission Issues](https://cwe.mitre.org/data/definitions/275.html)

[CWE-276 Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)

[CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

[CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

[CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

[CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

[CWE-377 Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

[CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html)

[CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)

[CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)

[CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)

[CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)

[CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)

[CWE-548 Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)

[CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

[CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html)

[CWE-601 URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

[CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

[CWE-651 Exposure of WSDL File Containing Sensitive Information](https://cwe.mitre.org/data/definitions/651.html)

[CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

[CWE-706 Use of Incorrectly-Resolved Name or Reference](https://cwe.mitre.org/data/definitions/706.html)

[CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

[CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)

[CWE-913 Improper Control of Dynamically-Managed Code Resources](https://cwe.mitre.org/data/definitions/913.html)

[CWE-922 Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

[CWE-1275 Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html)
