import numpy as np


class PixelFuzzer:
    def mutate_pixels(self, dataset):
        """Introduce subtle pixel corruptions.

        NOTE: If the dataset has been mutated by header_fuzzer with invalid
        dimension values (e.g., Columns=0, Rows=2147483647), accessing
        pixel_array will fail validation. We check for PixelData tag instead
        of using hasattr() which triggers the property getter.
        """
        # Check if PixelData tag exists without triggering validation
        if "PixelData" in dataset:
            try:
                pixels = dataset.pixel_array.copy()

                # Random noise injection
                noise_mask = np.random.random(pixels.shape) < 0.01  # 1% corruption
                pixels[noise_mask] = np.random.randint(0, 255, np.sum(noise_mask))

                dataset.PixelData = pixels.tobytes()
            except (ValueError, AttributeError, TypeError):
                # Pixel data access failed (invalid dimensions from header fuzzing)
                # Expected with corrupted headers - skip pixel mutations
                pass
        return dataset
