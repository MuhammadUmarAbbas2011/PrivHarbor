import json
import os
from rest_framework.views import APIView
from rest_framework.response import Response
from phishing_checker import AdvancedURLSecurityScanner
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import json
import time
import requests
from rest_framework.parsers import MultiPartParser, FormParser


VT_API_KEY = os.getenv('VT_API_KEY')  # Replace with your VirusTotal API key

class PhishingChecker(APIView):
    def post(self, request):
        url = request.data.get('url')

        if not url:
            return Response(
                {"error": "'url' field is required and cannot be empty."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            adurl = AdvancedURLSecurityScanner(url=url)
            response = adurl.run_full_scan()

            try:
                response_dict = json.loads(response)
            except json.JSONDecodeError:
                return Response(
                    {"error": "Scan response could not be parsed as JSON."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            return Response(
                {
                    "is_safe": response_dict.get("is_safe"),
                    "reasons": response_dict.get("reasons", [])
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"error": f"Internal error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )



class MalwareScanView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, format=None):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file provided.'}, status=status.HTTP_400_BAD_REQUEST)

        vt_url = 'https://www.virustotal.com/api/v3/files'
        headers = {'x-apikey': VT_API_KEY}
        files = {'file': (file.name, file.read())}

        upload_response = requests.post(vt_url, headers=headers, files=files)
        if upload_response.status_code != 200:
            return Response({'error': 'Failed to upload file to VirusTotal.'}, status=upload_response.status_code)

        file_id = upload_response.json()['data']['id']

        analysis_url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'
        while True:
            analysis_response = requests.get(analysis_url, headers=headers)
            if analysis_response.status_code != 200:
                return Response({'error': 'Failed to fetch analysis report.'}, status=analysis_response.status_code)

            data = analysis_response.json()
            status_str = data['data']['attributes']['status']
            if status_str == 'completed':
                results = data['data']['attributes']['results']
                malicious = {
                    engine: res for engine, res in results.items()
                    if res.get('category') == 'malicious'
                }
                return Response({
                    'file_name': file.name,
                    'malicious_count': len(malicious),
                    'total_engines': len(results),
                    'malicious_engines': malicious
                })

            time.sleep(3)