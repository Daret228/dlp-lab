"""Bounded lifecycle requests for the two interactive lab monitors."""
import threading
from . import service
from .policy import keys


class ControlError(RuntimeError):
    pass


class MonitorControl:
    def __init__(self, policy_store):
        self.policy_store = policy_store
        self.lock = threading.Lock()

    def execute(self, request):
        keys(request, ('component', 'action'))
        component, action = request['component'], request['action']
        if component not in ('files', 'text', 'signal-local') or action not in ('start', 'stop') or (component == 'signal-local' and action != 'start'):
            raise ValueError('Unsupported operation')
        # Requests cannot supply units, commands, paths or additional scope.
        with self.lock:
            try:
                state = service.unit_status(component)
                active = state.get('ActiveState')
                if action == 'start':
                    if active not in ('inactive', 'failed'):
                        raise ControlError('Модуль уже запущен или меняет состояние. Обновите статус.')
                    version = self.policy_store.get()['version']
                    command = service.launch_command(component, self.policy_store.path,
                                                     marker='DLP_TEST', seconds=120)
                    if active == 'failed':
                        service._run(['systemctl', '--user', 'reset-failed', service.UNITS[component]])
                    service._run(command)
                else:
                    version = None
                    if state.get('LoadState') != 'not-found':
                        service._run(['systemctl', '--user', 'stop', service.UNITS[component]])
                current = service.unit_status(component)
            except (OSError, ValueError):
                raise ControlError('Команда не подтверждена. Проверьте статус и журнал перед повтором.') from None
            return {'component': component, 'action': action,
                    'active': current.get('ActiveState', 'unknown'),
                    'policy_at_request': version,
                    'applied_policy_confirmed': False,
                    'message': ('Проверка сохранённых сообщений Signal запущена. Результат появится в карточке и журнале.' if component == 'signal-local' else
                                'Команда запуска выполнена. Готовность проверяйте по событию monitor_started или text_monitor_started.'
                                if action == 'start' else 'Команда остановки выполнена. Контроль остановленного модуля снят.')}
