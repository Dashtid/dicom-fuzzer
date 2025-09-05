class PixelFuzzer:
    def mutate_pixels(self, dataset):
        """Introduce subtle pixel corruptions"""
        if hasattr(dataset, 'pixel_array'):
            pixels = dataset.pixel_array.copy()
            
            # Random noise injection
            noise_mask = np.random.random(pixels.shape) < 0.01  # 1% corruption
            pixels[noise_mask] = np.random.randint(0, 255, np.sum(noise_mask))
            
            dataset.PixelData = pixels.tobytes()
        return dataset