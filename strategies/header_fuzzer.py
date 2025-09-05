class HeaderFuzzer:
    def mutate_tags(self, dataset):
        """Mutate DICOM tags with edge cases"""
        mutations = [
            self._overlong_strings,
            self._missing_required_tags,
            self._invalid_vr_values,
            self._boundary_values
        ]
        
        for mutation in random.sample(mutations, k=random.randint(1, 3)):
            dataset = mutation(dataset)
        return dataset
    
    def _overlong_strings(self, dataset):
        """Insert extremely long strings"""
        if hasattr(dataset, 'InstitutionName'):
            dataset.InstitutionName = "A" * 1024  # Way over normal limit
        return dataset