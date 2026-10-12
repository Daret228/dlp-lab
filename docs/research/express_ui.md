# eXpress Desktop: исследование UI (план)

Клиент не обнаружен проверенными способами; executable, версия, GUI-framework,
accessibility tree и фактический runtime backend **UNKNOWN**.

| Проверка | X11 | Wayland |
|---|---|---|
| Идентификация поля draft | UNKNOWN | UNKNOWN |
| Чтение значения | UNKNOWN | UNKNOWN |
| Событие отправки | UNKNOWN | UNKNOWN |
| Возможность синхронно запретить отправку | UNKNOWN | UNKNOWN |

После определения тестовой сборки повторить проверки, перечисленные в
telegram_ui.md, независимо от результатов Telegram. ExpressAdapter должен
объявлять реальные capabilities. Отсутствие подходящего API — документированное
ограничение; TextMonitor до подтверждения не реализуется.
