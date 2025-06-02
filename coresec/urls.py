from django.urls import path
from .views import PhishingChecker , MalwareScanView

urlpatterns = [
    path('phishing/check/',PhishingChecker.as_view(),name="phising-checker"),
    path('api/malware-scan/', MalwareScanView.as_view(), name='malware-scan'),
]