from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import re
import requests
import json
from .utils import *


class UrlValidateippath(APIView):

    def get(self, request, url_string):
        if validate_ip(url_string):
            final_response = dict()
            final_response['urlscan'] = list(urlscan(url_string))
            virus_scan, status_code, malicious = virusscanip(url_string)
            final_response['virustotal'] = [virus_scan, status_code]
            final_response['malicious'] = malicious
            return Response(final_response, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_404_NOT_FOUND)

    def post(self, request):
        ip = request.body.get('ip')
        print(ip)
        return Response(status=status.HTTP_200_OK)


class UrlValidatedomainpath(APIView):

    def get(self, request, url_string):
        if validate_domain(url_string):
            final_response = dict()
            final_response['urlscan'] = list(urlscan(url_string))
            virus_scan, status_code, malicious = virusscandomain(url_string)
            final_response['virustotal'] = [virus_scan, status_code]
            final_response['malicious'] = malicious
            return Response(final_response, status=status.HTTP_200_OK)

        return Response(status=status.HTTP_404_NOT_FOUND)


class UrlValidatePost(APIView):
    def post(self, request):
        request = json.loads(request.body)
        if 'ip' in request.keys():
            url_string = request['ip']
            if validate_ip(url_string):
                final_response = dict()
                final_response['urlscan'] = list(urlscan(url_string))
                virus_scan, status_code, malicious = virusscanip(url_string)
                final_response['virustotal'] = [virus_scan, status_code]
                final_response['malicious'] = malicious
                return Response(final_response, status=status.HTTP_200_OK)
            return Response(status=status.HTTP_404_NOT_FOUND)
        elif 'domain' in request.keys():
            url_string = request['domain']
            if validate_domain(url_string):
                final_response = dict()
                final_response['urlscan'] = list(urlscan(url_string))
                virus_scan, status_code, malicious = virusscandomain(url_string)
                final_response['virustotal'] = [virus_scan, status_code]
                final_response['malicious'] = malicious
                return Response(final_response, status=status.HTTP_200_OK)

            return Response(status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(status=status.HTTP_404_NOT_FOUND)


class UrlValidateParams(APIView):

    def get(self, request):
        type = request.GET.get('type')
        url_string = request.GET.get('data', None)
        if type not in ['ip', 'domain'] or not url_string:
            return Response(status=status.HTTP_404_NOT_FOUND)

        if type == 'domain':
            if validate_domain(url_string):
                final_response = dict()
                final_response['urlscan'] = list(urlscan(url_string))
                virus_scan, status_code, malicious = virusscandomain(url_string)
                final_response['virustotal'] = [virus_scan, status_code]
                final_response['malicious'] = malicious
                return Response(final_response, status=status.HTTP_200_OK)

            return Response(status=status.HTTP_404_NOT_FOUND)
        else:
            if validate_ip(url_string):
                final_response = dict()
                final_response['urlscan'] = list(urlscan(url_string))
                virus_scan, status_code, malicious = virusscanip(url_string)
                final_response['virustotal'] = [virus_scan, status_code]
                final_response['malicious'] = malicious
                return Response(final_response, status=status.HTTP_200_OK)
            return Response(status=status.HTTP_404_NOT_FOUND)
