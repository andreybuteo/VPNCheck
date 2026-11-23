# Реестр контрольных точек

Дата проверки источников: **2026-09-13**. Профиль: `internal/registry/default.json`, `profileVersion: 1`.

Метод: назначение каждого хоста подтверждалось только по официальной документации вендора
(без обращений к самим хостам). Тип `https` назначен только там, где вендор документирует
небольшой публичный ресурс без авторизации с предсказуемым статусом ответа. Всё остальное — `tls`
(DNS → TCP 443 → TLS с проверкой сертификата, без HTTP-запроса).

Важно: доступность контрольного узла не доказывает полноценную работу приложения. `401` от API
означает «сервер ответил, требуется авторизация», а не «API работает полностью».

## Точки

| ID | Хост | Тип | URL / ожидаемый статус | Источник | Примечание |
| --- | --- | --- | --- | --- | --- |
| openai-chatgpt | chatgpt.com | tls | — | [OpenAI Help: Network recommendations](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps) | |
| openai-api | api.openai.com | https | `/v1/models` → 401 | [Models list](https://developers.openai.com/api/docs/api-reference/models/list), [Error codes](https://developers.openai.com/api/docs/guides/error-codes) | Без ключа; 401 документирован для неверного ключа, отсутствие ключа выведено по аналогии |
| openai-cdn | cdn.oaistatic.com | tls | — | тот же список OpenAI | **Выключена**: вендор указывает только `*.oaistatic.com` |
| anthropic-web | claude.ai | tls | — | [Claude Code: corporate proxy](https://code.claude.com/docs/en/corporate-proxy) | |
| anthropic-api | api.anthropic.com | https | `/v1/models` → 401 | [Models list](https://platform.claude.com/docs/en/api/models-list), [Errors](https://platform.claude.com/docs/en/api/errors) | Заголовок `Anthropic-Version: 2023-06-01`, без ключа |
| autodesk-accounts | accounts.autodesk.com | tls | — | [Ports and Domains required by Autodesk Fusion](https://help.autodesk.com/view/fusion360/ENU/?caas=caas%2Fsfdcarticles%2Fsfdcarticles%2FFusion-360-cannot-access-the-services-through-proxy.html) | |
| autodesk-signin | signin.autodesk.com | tls | — | та же статья | |
| autodesk-idp | idp.auth.autodesk.com | tls | — | та же статья | |
| autodesk-fusionapi | fusionapi.autodesk.com | tls | — | та же статья | |
| autodesk-aps | developer.api.autodesk.com | tls | — | [URLs for Autodesk Subscription Licensing](https://help.autodesk.com/view/fusion360/ENU/?caas=caas%2Fsfdcarticles%2Fsfdcarticles%2FWhat-URLs-protocols-should-be-accessible-for-Desktop-Subscription-to-work-html.html) | В статье о Fusion покрыт только `*.api.autodesk.com` |
| google-www | www.google.com | tls | — | [Workspace host name allowlist](https://knowledge.workspace.google.com/admin/getting-started/set-up-a-google-workspace-host-name-allowlist) | `/generate_204` официально не документирован — не используется |
| google-accounts | accounts.google.com | https | `/.well-known/openid-configuration` → 200 | [Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect) | |
| gdrive-web | drive.google.com | tls | — | [Drive firewall and proxy settings](https://knowledge.workspace.google.com/admin/drive/drive-and-sites-firewall-and-proxy-settings) | |
| youtube-www | www.youtube.com | tls | — | [IFrame Player API](https://developers.google.com/youtube/iframe_api_reference) | |
| youtube-img | i.ytimg.com | tls | — | Workspace allowlist | **Выключена**: вендор указывает только `*.ytimg.com` |
| telegram-web | web.telegram.org | tls | — | [telegram.org/apps](https://telegram.org/apps) | Не проверка MTProto |
| telegram-site | telegram.org | tls | — | [telegram.org/apps](https://telegram.org/apps) | |
| telegram-botapi | api.telegram.org | tls | — | [Bot API](https://core.telegram.org/bots/api) | Ответ без токена не документирован |
| github-web | github.com | tls | — | [GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) | |
| github-api | api.github.com | https | `/` → 200 | [REST: meta](https://docs.github.com/en/rest/meta/meta) | Анонимный лимит по IP: [rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api) |
| github-raw | raw.githubusercontent.com | tls | — | [Copilot allowlist reference](https://docs.github.com/en/copilot/reference/copilot-allowlist-reference) | |
| github-objects | objects.githubusercontent.com | tls | — | GitHub-hosted runners | |
| docker-hub | hub.docker.com | tls | — | [Docker Desktop allow-list](https://docs.docker.com/desktop/setup/allow-list/) | |
| docker-registry | registry-1.docker.io | https | `/v2/` → 401 (или 200) | [Registry API spec](https://distribution.github.io/distribution/spec/api/), [Registry auth](https://docs.docker.com/reference/api/registry/auth/) | |
| docker-auth | auth.docker.io | tls | — | Registry auth | |
| npm-registry | registry.npmjs.org | https | `/-/ping` → 200 | [npm ping](https://docs.npmjs.com/cli/v11/commands/npm-ping) | Документирован через CLI |
| pypi-web | pypi.org | https | `/stats/` → 200 | [PyPI stats API](https://docs.pypi.org/api/stats/) | Требует `Accept: application/json` |
| pypi-files | files.pythonhosted.org | tls | — | [PyPI index API](https://docs.pypi.org/api/index-api/) | |
| hf-hub | huggingface.co | tls | — | [Hub API](https://huggingface.co/docs/hub/api), [rate limits](https://huggingface.co/docs/hub/rate-limits) | |
| ms-login | login.microsoftonline.com | https | `/common/v2.0/.well-known/openid-configuration` → 200 | [Microsoft identity platform OIDC](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc) | |
| cloudflare-www | www.cloudflare.com | https | `/cdn-cgi/trace` → 200 | [cdn-cgi endpoint](https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/) | Ответ содержит IP клиента; тело не сохраняется |
| ru-direct-yandex | yandex.ru | tls | — | [Яндекс Интернетометр](https://yandex.ru/internet) | Группа «Россия напрямую», см. ниже |

Итого 31 точка, 29 включены по умолчанию, 2 выключены с указанием причины.

## Внешний IP (опция, по умолчанию выключена)

Провайдер: Cloudflare `https://www.cloudflare.com/cdn-cgi/trace` — без ключа, поля `ip=` и `loc=`
(код страны). Опубликованных лимитов для этого диагностического ресурса нет
([документация](https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/)).
ASN этот источник не отдаёт, поэтому показывается «нет данных». Запрос выполняется только при
включённой опции, дважды за запуск (в начале и в конце), через выбранный маршрут.

## Россия напрямую (проверка раздельной маршрутизации, с версии 4.3)

Если выбрана группа «Россия напрямую», после проб выполняется один GET страницы
`https://yandex.ru/internet` (около 110 КБ, читается не больше 256 КБ) через выбранный маршрут и
ограничитель. Из встроенных в страницу данных берутся `"ip":{"v4":…}` и `"isVpn"`. Этот адрес
сравнивается с адресом выхода по Cloudflare trace (он запрашивается автоматически). Короткий ответ
`/internet/api/v0/ip` не используется: в проверке 2026-11-23 он вернул `"127.0.0.1"` вместо адреса.
Ответ с проверкой на робота (3xx, 403, 429, `showcaptcha`) даёт вердикт «адрес не определён».

Страны на странице Яндекса нет (только город), поэтому страна этого адреса запрашивается у RIPEstat:
`https://stat.ripe.net/data/maxmind-geo-lite/data.json?sourceapp=vpncheck&resource=<адрес>`
([описание](https://stat.ripe.net/docs/data-api/api-endpoints/maxmind-geo-lite)), один небольшой GET
через тот же маршрут и только если адреса Яндекса и Cloudflare различаются (иначе страна берётся у
Cloudflare). Это единственный запрос, в котором программа передаёт адрес наружу: RIPE NCC
получает адрес, который видит Яндекс.

## Что не удалось подтвердить

- Официальная страница OpenAI отдаёт 403 автоматическим клиентам; прочитана в браузере.
- Статья GitHub «About GitHub and GitHub domains» больше не существует (404); использованы
  справочник GitHub-hosted runners и Copilot allowlist reference.
- Для `huggingface.co` не удалось прочитать спецификацию `GET /api/models`, поэтому только TLS.
