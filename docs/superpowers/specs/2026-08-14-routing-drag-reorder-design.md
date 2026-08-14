# Drag-and-drop перестановка правил в Routing (дизайн)

Дата: 2026-08-14
Статус: согласовано в чате

## Контекст

Вкладка Routing (`bins/outline-ui/frontend/src/features/ws/Routing.svelte`)
переставляет правила `[[route]]` кнопками ↑/↓ (`move()` →
`routesReorder(from, to, revision)`). Бэкенд reorder
(`/control/routes/reorder`, `apply_reorder`) готов и починен (commit
`01919141` — position-фикс). Рабочий паттерн drag-and-drop уже есть в
`UplinkDrawer.svelte` (перестановка fallback-ов).

## Цель

Добавить перетаскивание правил мышью, СОХРАНИВ кнопки ↑/↓ (клавиатура /
screen-reader).

## Дизайн

Точно по образцу `UplinkDrawer.svelte` (`handleDragStart/DragOver/DragLeave/
Drop/DragEnd`, `draggingKey`/`dragOverKey`):

- К каждой строке таблицы правил — drag-handle `⠿` и `draggable`; состояния
  `draggingIndex`/`dragOverIndex` для подсветки (тянущаяся строка
  полупрозрачная, строка-цель — рамка). Переиспользовать существующие
  CSS-классы (`dragging`/`drag-over`/`drag-handle`), которые уже есть в
  `app.css` под drag fallback-ов.
- На `drop`: `from` (тянутая) → `to` (цель), вызов существующего
  `routesReorder(from, to, revision)` c текущим `revision` из последнего poll.
- Кнопки ↑/↓ остаются без изменений.
- **`default`-правило** не перетаскивается (`draggable=false` на его строке) и
  не принимает drop, который увёл бы не-default ниже него — та же защита
  «default последний», что у стрелок (↑ disabled на default, ↓ на строке над
  default).
- **Только фронт** (`Routing.svelte`). Бэкенд/прокси/ws-rust не трогаем.

## Тестирование

Unit-тесты не нужны: логика — DOM drag-события, вычисление `from/to`
тривиально и уже покрыто бэкенд-тестами reorder (`reorder_moves_rule`).
Проверка: `pnpm run check` + `pnpm exec vitest run` (регрессий нет) +
`pnpm run build` + визуально после раскатки.

## Раскатка

Новый образ `outline-ui:1.0.4` в k3s через containerd узла `.51`
(docker build --provenance=false → k3s ctr import+push → kubectl set image;
см. [[k3s-unreachable-from-cc-bash-sandbox]]). ws-rust узлы НЕ затрагиваются.
