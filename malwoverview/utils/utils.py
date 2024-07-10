from urllib.parse import urlparse
import geocoder
import socket


def urltoip(urltarget):
    geoloc = ''
    target = ''
    finalip = ''
    result = ''

    try:
        target = urlparse(urltarget)
        result = target.netloc
        finalip = socket.gethostbyname(result)
        if finalip is not None:
            geoloc = geocoder.ip(finalip)
            if (geoloc is not None):
                return geoloc.city
            else:
                result = ''
                return result
        else:
            result = "Not Found"
            return result
    except Exception:
        result = "Not Found"
        return result
