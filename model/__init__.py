from kitty.model import *

# Data models

# Based on this model, Kitty will generate various mutations of the template,
# each mutation is constructed from a mutation of one of the fields, and the
# default values of the rest of them. When a field has no more mutations, it
# will return it to its default value, and move to the next field.

# a general data model for HTTP
http_get_v1 = Template(name='HTTP_GET_V1', fields=[
    String('GET', name='method'),           # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1'),          # 1.a The space between Method and Path
    String('/index.html', name='path'),     # 2. Path - a string with the value "/index.html"
    Delimiter(' ', name='space2'),          # 2.a. The space between Path and Protocol
    String('HTTP/1.1', name='protocol'),    # 3. Protocol - a string with the value "HTTP/1.1"
    Delimiter('\r\n\r\n', name='eom'),      # 4. The double "new lines" ("\r\n\r\n") at the end of the http request
])

# a more detailed data model for HTTP
http_get_v2 = Template(name='HTTP_GET_V2', fields=[
    String('GET', name='method'),               # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1'),              # 1.a The space between Method and Path
    String('/index.html', name='path'),         # 2. Path - a string with the value "/index.html"
    Delimiter(' ', name='space2'),              # 2.a. The space between Path and Protocol
    String('HTTP', name='protocol name'),       # 3.a Protocol Name - a string with the value "HTTP"
    Delimiter('/', name='fws1'),                # 3.b The '/' after "HTTP"
    Dword(1, name='major version',              # 3.c Major Version - a number with the value 1
          encoder=ENC_INT_DEC)                  # encode the major version as decimal number
    Delimiter('.', name='dot1'),                # 3.d The '.' between 1 and 1
    Dword(1, name='major version',              # 3.e Minor Version - a number with the value 1
          encoder=ENC_INT_DEC)                  # encode the minor version as decimal number
    Delimiter('\r\n\r\n', name='eom')           # 4. The double "new lines" ("\r\n\r\n") at the end of the request
])

# Static / fuzzable=False
http_get_v3 = Template(name='HTTP_GET_V3', fields=[
    String('GET', name='method', fuzzable=False),   # 1. Method - a string with the value "GET"
    Delimiter(' ', name='space1', fuzzable=False),  # 1.a The space between Method and Path
    String('/index.html', name='path'),             # 2. Path - a string with the value "/index.html"
    Delimiter(' ', name='space2'),                  # 2.a. The space between Path and Protocol
    String('HTTP', name='protocol name'),           # 3.a Protocol Name - a string with the value "HTTP"
    Delimiter('/', name='fws1'),                    # 3.b The '/' after "HTTP"
    Dword(1, name='major version',                  # 3.c Major Version - a number with the value 1
          encoder=ENC_INT_DEC)                      # encode the major version as decimal number
    Delimiter('.', name='dot1'),                    # 3.d The '.' between 1 and 1
    Dword(1, name='major version',                  # 3.e Minor Version - a number with the value 1
          encoder=ENC_INT_DEC)                      # encode the minor version as decimal number
    Static('\r\n\r\n', name='eom')                  # 4. The double "new lines" ("\r\n\r\n") at the end of the request
])
