from django.core.management.base import BaseCommand
from core.models_keystroke import KeystrokeDynamics
from core.models import User
import pandas as pd

class Command(BaseCommand):
    help = 'Export keystroke dynamics data for ML pipeline.'

    def handle(self, *args, **options):
        data = []
        for k in KeystrokeDynamics.objects.all():
            user = k.user.username
            session = k.session_id
            events = k.event_data
            # Example feature extraction: average hold time, average flight time
            hold_times = []
            flight_times = []
            last_keyup_time = None
            for e in events:
                if e['type'] == 'keydown':
                    hold_start = e['time']
                elif e['type'] == 'keyup':
                    hold_end = e['time']
                    if 'hold_start' in locals():
                        hold_times.append(hold_end - hold_start)
                        del hold_start
                    if last_keyup_time is not None:
                        flight_times.append(hold_end - last_keyup_time)
                    last_keyup_time = hold_end
            avg_hold = sum(hold_times)/len(hold_times) if hold_times else 0
            avg_flight = sum(flight_times)/len(flight_times) if flight_times else 0
            data.append({
                'user': user,
                'session': session,
                'avg_hold_time': avg_hold,
                'avg_flight_time': avg_flight
            })
        df = pd.DataFrame(data)
        df.to_csv('ml_pipeline/data_generation/keystroke_features.csv', index=False)
        self.stdout.write(self.style.SUCCESS('Exported keystroke features.'))
