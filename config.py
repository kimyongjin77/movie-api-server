#JWT 환경설정
class Config:
    #보안키 셋팅(비공개)
    JWT_SECRET_KEY = 'yhacademy1029##heelo'
    #유효기간 설정 여부
    JWT_ACCESS_TOKEN_EXPIRES = False
    PROPAGATE_EXCEPTIONS = True
