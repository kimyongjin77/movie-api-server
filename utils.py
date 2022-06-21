from passlib.hash import pbkdf2_sha256

#원문 비밀번호를 암호화 하는 함수, 암호화된 데이터 리턴한다.
#hash(단방향암호화) : 암호화는 되나 복호화는 되지 않는다.
def hash_password(original_password):
    #시드(비공개 데이터)
    salt='yh*hello12'
    #원본에 시드를 붙인다.
    password=original_password+salt
    #단방향암호화한다.
    password=pbkdf2_sha256.hash(password)
    return password

#비밀번호가 맞는지 확인하는 함수, True/False를 리턴한다.
def check_password(original_password, hashed_password):
    #시드(비공개 데이터)
    salt='yh*hello12'
    #맞으면 True, 틀리면 False
    check=pbkdf2_sha256.verify(original_password+salt, hashed_password)
    return check