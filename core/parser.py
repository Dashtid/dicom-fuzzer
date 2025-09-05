class DICOMParser:
    def __init__(self, file_path):
        self.original_file = file_path
        self.dataset = pydicom.dcmread(file_path)
        
    def extract_metadata(self):
        """Extract key metadata for mutation"""
        return {
            'patient_id': self.dataset.get('PatientID', ''),
            'patient_name': self.dataset.get('PatientName', ''),
            'study_date': self.dataset.get('StudyDate', ''),
            'modality': self.dataset.get('Modality', ''),
            'institution': self.dataset.get('InstitutionName', ''),
            # Add more fields as needed
        }
    
    def get_pixel_data(self):
        """Extract pixel array if present"""
        if hasattr(self.dataset, 'pixel_array'):
            return self.dataset.pixel_array
        return None