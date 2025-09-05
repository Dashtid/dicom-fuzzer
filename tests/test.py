def test_application_with_fuzzed_files(fuzzed_files, app_endpoint):
    """Feed generated files to your application"""
    results = []
    
    for file_path in fuzzed_files:
        try:
            # Upload to your app (HTTP, file system, etc.)
            response = upload_to_app(file_path, app_endpoint)
            results.append({
                'file': file_path.name,
                'status': 'success',
                'response': response
            })
        except Exception as e:
            results.append({
                'file': file_path.name, 
                'status': 'error',
                'error': str(e)
            })
    
    return results