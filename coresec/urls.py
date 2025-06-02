from django.urls import path
from .views import PhishingChecker , MalwareScanView , DomainReputationView

urlpatterns = [
    path('phishing/check/',PhishingChecker.as_view(),name="phising-checker"),
    path('malware-scan/', MalwareScanView.as_view(), name='malware-scan'),
    path('domain-reputation/', DomainReputationView.as_view(), name='domain-reputation'),
]