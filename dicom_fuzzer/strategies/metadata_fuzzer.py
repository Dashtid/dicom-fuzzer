import random
from datetime import datetime, timedelta


class MetadataFuzzer:
    def __init__(self):
        self.fake_names = ["Smith^John", "Doe^Jane", "Johnson^Mike"]
        self.fake_ids = [f"PAT{i:06d}" for i in range(1000, 9999)]

    def mutate_patient_info(self, dataset):
        """Generate believable but fake patient data"""
        dataset.PatientID = random.choice(self.fake_ids)
        dataset.PatientName = random.choice(self.fake_names)
        dataset.PatientBirthDate = self._random_date()
        return dataset

    def _random_date(self):
        """Generate random but valid DICOM date"""
        start_date = datetime(1950, 1, 1)
        end_date = datetime(2010, 12, 31)
        random_date = start_date + timedelta(
            days=random.randint(0, (end_date - start_date).days)
        )
        return random_date.strftime("%Y%m%d")
