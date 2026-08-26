# Автоимя сервера из hostname ссылки (дизайн)

Дата: 2026-08-26
Статус: согласовано в чате

## Контекст

Диалог добавления/редактирования сервера — `ProfileEditorDialog`
([MainActivity.kt:610](../../../android/app/src/main/java/com/outline/proxy/MainActivity.kt)).
Поле **Name** необязательное; при сохранении `save()` собирает профиль
`initial.copy(name = name, …)` без какой-либо подстановки, поэтому пустое имя так
и сохраняется пустым.

Адрес сервера приходит из одного из трёх источников
([ServerProfile.kt](../../../android/app/src/main/java/com/outline/proxy/ServerProfile.kt)):

- `vlessLink` — `vless://UUID@host:port?params#remark`;
- `ssLink` — `ss://base64(method:pass)@host:port#tag` (SIP002);
- `configUrl` — HTTPS-URL подписки.

Пустое имя деградирует корректно: главный экран показывает
`profile?.name?.takeIf { it.isNotBlank() } ?: "No server"`, нотификация опускает
` · name`. То есть фича — про удобство, а не про корректность.

## Цель

Если при сохранении сервера поле **Name пусто**, подставить в него имя из
заполненного источника: **`#remark`-метку ссылки, а если её нет — hostname**.
Так безымянный сервер получает человекочитаемое имя (`vless://…#Germany` →
«Germany»), а при отсутствии метки — хотя бы хост.

## Не-цели (YAGNI)

- **Живой автоввод в поле по мере набора ссылки.** Подстановка — только на
  сохранении.
- **Валидация/нормализация ссылки** сверх извлечения remark/host.

## Архитектура

### Извлечение имени — чистый Kotlin

Три функции-хелпера (в `ServerProfile.companion`), **без `android.net.Uri`**:

- `remarkOf(link: String): String?` — часть после **последнего** `#`;
  `URLDecoder.decode(frag, "UTF-8")` (percent-декод, `+`→пробел не нужен — это
  fragment, но decode безопасен), `trim()`; `null`, если метки нет или пуста.
- `hostOf(link: String): String?`:
  - обрезать до `://` (если есть), взять остаток;
  - отрезать по первому из `/ ? #` → остаётся authority;
  - отбросить `userinfo@` (по **последнему** `@` — у `ss://` userinfo это base64);
  - снять `:port`; поддержать IPv6-литерал `[2001:db8::1]` (вернуть без скобок);
  - `null`/пусто, если host не выделяется.
- `deriveName(link: String): String?` = `remarkOf(link) ?: hostOf(link)` —
  **remark в приоритете, hostname как fallback**.

Причина отказа от `android.net.Uri`: он не юнит-тестируется чистым JUnit
(нужен Robolectric) и спотыкается на base64-userinfo `ss://`. Строковый парс и
`URLDecoder` тестируются как `LinkQuality`/`LinkInfo`, файл теста — рядом
(`app/src/test/.../ServerNameTest.kt`).

### Точка подстановки

В `ProfileEditorDialog.save()`, до `initial.copy(...)`:

```
val derived = name.ifBlank {
    val src = when {
        configUrl.isNotBlank() -> configUrl
        transport == "vless"   -> vlessLink
        else                   -> ssLink
    }
    ServerProfile.deriveName(src).orEmpty()
}
val base = initial.copy(name = derived, …)
```

Приоритет источника: подписка (`configUrl`) → иначе выбранный transport-линк.
Для https-подписки `remarkOf` обычно `null`, поэтому имя = hostname. Если всё
пусто — `derived` остаётся пустым (текущее поведение).

## Тестирование

- **Unit** `deriveName`/`remarkOf`/`hostOf`: vless с `#remark` (plain,
  percent-encoded, emoji-флаг) → remark; vless/ss **без** метки → hostname;
  ss с base64-userinfo; https-URL → hostname; IPv6-литерал; хвостовые
  `?query`/`/path`; мусор → `null`.
- **Ручная проверка:** добавить сервер, оставить Name пустым; со ссылкой с меткой
  → имя-remark; со ссылкой без метки и с https-подпиской → имя-hostname.

## Связь с локализацией

Производное имя — данные пользователя, **не переводится**. Пересечение с
[локализацией](2026-08-26-android-i18n-system-locale-design.md) только в том, что
сам диалог сервера всё равно переводится в рамках той фичи. Обе фичи можно
реализовать одним заходом/планом.
