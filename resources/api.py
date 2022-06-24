from datetime import datetime, timedelta
from http import HTTPStatus
import http
from flask import request
from flask_jwt_extended import create_access_token, get_jwt, get_jwt_identity, jwt_required
from flask_restful import Resource
from mysql.connector.errors import Error
from mysql_connection import get_connection
import mysql.connector
from email_validator import validate_email, EmailNotValidError

from utils import check_password, hash_password
import numpy as np
import pandas as pd

#회원관리
# 경로 : /user
class User(Resource):
    # 회원가입저장
    # 메소드 : post
    # 데이터 : email, password, name, gender
    def post(self):
        #클라이언트에서 보낸 body의 json데이터를 받아오는 코드
        # {
        #     "name": "홍길동",
        #     "email": "abc@naver.com",
        #     "password": "1234",
        #     "gender": "Male/Female"
        # }
        data=request.get_json()
        #print(data)

        name=data['name']
        email=data['email']
        password=data['password']
        gender=data['gender']

        #이메일 주소형식이 제대로 된 주소형식인지 확인하는 코드 작성.
        try:
            # Validate & take the normalized form of the email
            # address for all logic beyond this point (especially
            # before going to a database query where equality
            # does not take into account normalization).
            validated_email = validate_email(email).email
            #print(validated_email)
            #return {"validate_email":"success"}, HTTPStatus.OK
        except EmailNotValidError as e:
            # email is not valid, exception message is human-readable
            #print('error : ' + str(e))
            return {"error":str(e)}, HTTPStatus.BAD_REQUEST

        #비밀번호 정책을 확인한다. 자리수는 4자리이상 12자리 이하로 가능하게...
        if len(password)<4 or len(password)>12:
            return {"error":'비밀번호 길이(4~12)를 확인하세요.'}, HTTPStatus.BAD_REQUEST

        #비밀번호를 암호화 한다.
        hashed_password=hash_password(password)
        #print(hashed_password)
        #print(check_password(password, hashed_password))

        try:
            # 데이터 인서트
            # db접속
            connection = get_connection()

            # 쿼리작성
            query='''insert into user
                    (name, email, password, gender)
                    values
                    (%s,%s,%s,%s)
                    ; '''

            record=(name, validated_email, hashed_password, gender)

            # 커서
            cursor=connection.cursor()

            # 실행
            cursor.execute(query, record)

            # 커밋
            connection.commit()

            # db에 저장된 아이디값 가져오기.
            # 자동증가된 id컬럼 값
            user_id=cursor.lastrowid

            #클라이언트에 user_id도 포함하여 응답해야 한다.
            #return {"result":"success", "user_id":user_id}, HTTPStatus.OK
            #user_id값은 보안이 중요하다, 해킹 가능성이 있으므로
            #JWT로 암호화해서 보낸다.
            access_token=create_access_token(user_id)

            return {"result":"success", "access_token":access_token}, HTTPStatus.OK

        except mysql.connector.Error as e:
            print(e)
            connection.rollback()
            return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE
        
        finally:
            cursor.close()
            connection.close()

    # 내정보(리뷰)조회
    # 메소드 : get
    # 데이터 : header:user_id토큰, params=?offset=0&limit=25
    # result : 내리뷰목록
    @jwt_required(optional=False)
    def get(self):

        offset=request.args['offset']
        limit=request.args['limit']

        #user_id를 create_access_token(user_id)로 암호화 했다.
        #인증토큰을 복호화 한다.
        user_id=get_jwt_identity()

        try:
            # db접속
            connection = get_connection()

            query='''select a.movieId, b.title, a.rating, a.contents, a.createdAt, a.updatedAt
                    from rating a join movie b
                        on a.movieId=b.id
                    where a.userId=%s
                    order by b.title
                    limit %s, %s
                    ;'''

            record=(user_id, int(offset), int(limit))

            # 커서(딕셔너리 셋으로 가져와라)
            #select문은 dictionary=True 한다.
            cursor=connection.cursor(dictionary=True)

            # 실행
            cursor.execute(query, record)
            
            # 데이터fetch : select문은 아래함수를 이용해서 데이터를 가져온다.
            result_list=cursor.fetchall()
            #print(result_list)

            #중요! db에서 가져온 timestamp데이터타입은 파이썬의 datetime으로 자동 변경된다.
            #이 데이터는 json으로 바로 보낼 수 없으므로 문자열로 바꿔서 다시 저장해서 보낸다.
            i=0
            for record in result_list:
                result_list[i]['createdAt'] = record['createdAt'].isoformat()
                result_list[i]['updatedAt'] = record['updatedAt'].isoformat()
                i=i+1

            return {"result":"success",
                    "count":len(result_list),
                    "items":result_list}, HTTPStatus.OK

        except mysql.connector.Error as e:
            print(e)
            return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE

        finally:
            # 자원해제
            #print('finally')
            cursor.close()
            connection.close()

jwt_blacklist=set()     #로그아웃 한 토큰 집합(데이터)
#로그인아웃관리
# 경로 : /login-out
class LoginOut(Resource):
    #로그인
    # 메소드 : get
    # 데이터(get은 params 쿼리스트링을 사용한다.) : email, password
    # result : user_id토큰 및 회원정보
    def get(self):
        #1.요청 body에서 데이터를 가져온다.
        #클라이언트에서 보낸 body의 json데이터를 받아오는 코드
        # {
        #     "email": "abc@naver.com",
        #     "password": "1234"
        # }
        # data=request.get_json()
        # #print(data)

        # email=data['email']
        # password=data['password']

        email=request.args['email']
        password=request.args['password']

        #2.이메일 검증
        #이메일 주소형식이 제대로 된 주소형식인지 확인하는 코드 작성.
        try:
            # Validate & take the normalized form of the email
            # address for all logic beyond this point (especially
            # before going to a database query where equality
            # does not take into account normalization).
            validated_email = validate_email(email).email
            #print(validated_email)
            #return {"validate_email":"success"}, HTTPStatus.OK
        except EmailNotValidError as e:
            # email is not valid, exception message is human-readable
            #print('error : ' + str(e))
            return {"error":"이메일 형식을 확인해 주세요"}, HTTPStatus.BAD_REQUEST

        #3.비밀번호 정책 확인
        #비밀번호 정책을 확인한다. 자리수는 4자리이상 12자리 이하로 가능하게...
        if len(password)<4 or len(password)>12:
            return {"error":'비밀번호 길이(4~12)를 확인하세요.'}, HTTPStatus.BAD_REQUEST

        #4.이메일로 사용자정보 조회
        try:
            # db접속
            connection = get_connection()

            query='''select *
                    from user
                    where email=%s
                    ;'''

            record=(validated_email,)

            # 커서(딕셔너리 셋으로 가져와라)
            #select문은 dictionary=True 한다.
            cursor=connection.cursor(dictionary=True)

            # 실행
            cursor.execute(query, record)
            
            # 데이터fetch : select문은 아래함수를 이용해서 데이터를 가져온다.
            result_list=cursor.fetchall()
            #print(result_list)

            if len(result_list) != 1:
                return {"error":"회원정보가 없습니다. 회원가입을 먼저 하세요"}, HTTPStatus.BAD_REQUEST

            #5.비밀번호 비교
            # check=check_password(password, result_list[0]['password'])
            # if check==False:
            #     return {"error":"비밀번호가 틀립니다. 확인하세요."}, HTTPStatus.BAD_REQUEST

            #중요! db에서 가져온 timestamp데이터타입은 파이썬의 datetime으로 자동 변경된다.
            #이 데이터는 json으로 바로 보낼 수 없으므로 문자열로 바꿔서 다시 저장해서 보낸다.
            i=0
            for record in result_list:
                result_list[i]['createdAt'] = record['createdAt'].isoformat()
                result_list[i]['updatedAt'] = record['updatedAt'].isoformat()
                i=i+1
            
            user_id=result_list[0]['id']
            name=result_list[0]['name']
            gender=result_list[0]['gender']

            #user_id값은 보안이 중요하다, 해킹 가능성이 있으므로
            #JWT로 암호화해서 보낸다.
            access_token=create_access_token(user_id)
            #토큰 유효기한 셋팅
            #access_token=create_access_token(user_id, expires_delta=timedelta(minutes=1))
            
            return {"result":"success",
                    "access_token":access_token,
                    "email":validated_email,
                    "name":name,
                    "gender":gender}, HTTPStatus.OK

        except mysql.connector.Error as e:
            print(e)
            return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE

        finally:
            # 자원해제
            #print('finally')
            cursor.close()
            connection.close()

    #로그아웃
    # 메소드 : post
    # 데이터 : header:user_id토큰
    @jwt_required(optional=False)
    def post(self):
        jti=get_jwt()['jti']        #토큰을 가져온다.
        #print(jti)
        jwt_blacklist.add(jti)      #토큰을 집합에 넣는다.
        return {"result":"success"}, HTTPStatus.OK

#영화관리
# 경로 : /movie/search
class MovieList(Resource):
    # 영화목록검색조회(즐겨찾기/상세내용)
    # 메소드 : get
    # 데이터 : header:user_id토큰, params=?offset=0&limit=25&sch_title&order_by=1&only_myfavorite=0
    # order_by=1 은 리뷰수, 2는 별점순
    # only_myfavorite=0 은 전체영화 중 검색, 1는 내 즐겨찾기된 영화 중 검색
    # result=영화목록
    @jwt_required(optional=True)
    def get(self):
        offset=request.args['offset']
        limit=request.args['limit']
        sch_title=request.args['sch_title']
        order_by=request.args['order_by']
        only_myfavorite=request.args['only_myfavorite']
        #user_id를 create_access_token(user_id)로 암호화 했다.
        #인증토큰을 복호화 한다.
        user_id=get_jwt_identity()
        #print('user_id :', user_id)     #없을 시 None

        try:
            # db접속
            connection = get_connection()

            query='''select count(b.movieId) review_cnt
                        ,convert(ifnull(avg(b.rating), 0), double) rating_avg 
                        ,a.id movieId
                        ,a.title
                        ,if(count(c.userId)>0, True, False) myfavorite
                        ,a.summary
                        ,convert(date(a.year), char) year
                        ,a.attendance
                    from movie a left join rating b
                        on a.id=b.movieId left join favorite c
                        on b.movieId=c.movieId and %s=c.userId
                    where a.title like concat('%', %s, '%')
                    group by a.id
                    having myfavorite=if(%s=0, myfavorite, True) 
                    order by %s desc
                    limit %s, %s
                    ;'''
            #DECIMAL, TIMESTAMP(DATETIME/DATE) 데이터타입은 json으로 변환할 수 없다.
            record=(user_id, sch_title, int(only_myfavorite), int(order_by), int(offset), int(limit))

            # 커서(딕셔너리 셋으로 가져와라)
            #select문은 dictionary=True 한다.
            cursor=connection.cursor(dictionary=True)

            # 실행
            cursor.execute(query, record)
            
            # 데이터fetch : select문은 아래함수를 이용해서 데이터를 가져온다.
            result_list=cursor.fetchall()
            #print(result_list)

            #중요! db에서 가져온 timestamp데이터타입은 파이썬의 datetime으로 자동 변경된다.
            #이 DECIMAL, datetime 컬럼타입 데이터는 json으로 바로 보낼 수 없으므로 float, 문자열로 바꿔서 다시 저장해서 보낸다.
            # i=0
            # for record in result_list:
            #     result_list[i]['rating_avg'] = float(record['rating_avg'])
            #     # result_list[i]['createdAt'] = record['createdAt'].isoformat()
            #     # result_list[i]['updatedAt'] = record['updatedAt'].isoformat()
            #     i=i+1

            return {"result":"success",
                    "count":len(result_list),
                    "items":result_list}, HTTPStatus.OK

        except mysql.connector.Error as e:
            print(e)
            return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE

        finally:
            # 자원해제
            #print('finally')
            cursor.close()
            connection.close()

#리뷰관리
# 경로 : /movie/review/<int:movie_id>
class Review(Resource):
    # 영화리뷰조회
    # 메소드 : get
    # 데이터 : header:user_id토큰, params=?offset=0&limit=25
    # result=영화리뷰목록
    @jwt_required(optional=True)
    def get(self, movie_id):
        offset=request.args['offset']
        limit=request.args['limit']
        #user_id를 create_access_token(user_id)로 암호화 했다.
        #인증토큰을 복호화 한다.
        user_id=get_jwt_identity()
        #print('user_id :', user_id)     #없을 시 None

        try:
            # db접속
            connection = get_connection()

            query='''select b.name
                        ,b.gender
                        ,a.rating
                        ,a.contents
                    from rating a join user b
                        on a.userId=b.id
                    where a.movieId=%s
                    order by a.rating desc
                    limit %s, %s
                    ;'''
            #DECIMAL, TIMESTAMP(DATETIME/DATE) 데이터타입은 json으로 변환할 수 없다.
            record=(movie_id, int(offset), int(limit))

            # 커서(딕셔너리 셋으로 가져와라)
            #select문은 dictionary=True 한다.
            cursor=connection.cursor(dictionary=True)

            # 실행
            cursor.execute(query, record)
            
            # 데이터fetch : select문은 아래함수를 이용해서 데이터를 가져온다.
            result_list=cursor.fetchall()
            #print(result_list)

            #중요! db에서 가져온 timestamp데이터타입은 파이썬의 datetime으로 자동 변경된다.
            #이 DECIMAL, datetime 컬럼타입 데이터는 json으로 바로 보낼 수 없으므로 float, 문자열로 바꿔서 다시 저장해서 보낸다.
            # i=0
            # for record in result_list:
            #     result_list[i]['rating_avg'] = float(record['rating_avg'])
            #     # result_list[i]['createdAt'] = record['createdAt'].isoformat()
            #     # result_list[i]['updatedAt'] = record['updatedAt'].isoformat()
            #     i=i+1

            return {"result":"success",
                    "count":len(result_list),
                    "items":result_list}, HTTPStatus.OK

        except mysql.connector.Error as e:
            print(e)
            return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE

        finally:
            # 자원해제
            #print('finally')
            cursor.close()
            connection.close()
    
    # 영화리뷰작성저장
    # 메소드 : post
    # 데이터 : header:user_id토큰, body=rating,contents
    # result=
    @jwt_required(optional=False)
    def post(self, movie_id):
        #클라이언트에서 보낸 body의 json데이터를 받아오는 코드
        # {
        #     "rating": 4,
        #     "contents": "",
        # }
        data=request.get_json()
        #print(data)

        rating=data['rating']
        contents=data['contents']

        #user_id를 create_access_token(user_id)로 암호화 했다.
        #인증토큰을 복호화 한다.
        user_id=get_jwt_identity()

        try:
            # 데이터 인서트
            # db접속
            connection = get_connection()

            # 쿼리작성
            query='''insert into rating
                    (userId, movieId, rating, contents)
                    values
                    (%s,%s,%s,%s)
                    ; '''

            record=(user_id, movie_id, rating, contents)

            # 커서
            cursor=connection.cursor()

            # 실행
            cursor.execute(query, record)

            # 커밋
            connection.commit()

            return {"result":"success"}, HTTPStatus.OK

        except mysql.connector.Error as e:
            connection.rollback()

            print("Error code:", e.errno)        # error number
            print("SQLSTATE value:", e.sqlstate) # SQLSTATE value
            print("Error message:", e.msg)       # error message
            print(e)

            if e.errno==1062:
                return {"error":"이미 리뷰가 존재합니다."}, HTTPStatus.BAD_REQUEST
            elif e.errno==1452:
                return {"error":"해당 영화는 존재하지 않습니다."}, HTTPStatus.BAD_REQUEST
            else:
                return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE
        
        finally:
            cursor.close()
            connection.close()

#즐겨찾기관리
# 경로 : /movie/favorite/<int:movie_id>
class Favorite(Resource):
    # 즐겨찾기저장
    # 메소드 : post
    # 데이터 : header:user_id토큰
    # result=
    @jwt_required(optional=False)
    def post(self, movie_id):
        #user_id를 create_access_token(user_id)로 암호화 했다.
        #인증토큰을 복호화 한다.
        user_id=get_jwt_identity()

        try:
            # 데이터 인서트
            # db접속
            connection = get_connection()

            # 쿼리작성
            query='''insert into favorite
                    (userId, movieId)
                    values
                    (%s,%s)
                    ; '''

            record=(user_id, movie_id)

            # 커서
            cursor=connection.cursor()

            # 실행
            cursor.execute(query, record)

            # 커밋
            connection.commit()

            return {"result":"success"}, HTTPStatus.OK

        except mysql.connector.Error as e:
            connection.rollback()

            print("Error code:", e.errno)        # error number
            print("SQLSTATE value:", e.sqlstate) # SQLSTATE value
            print("Error message:", e.msg)       # error message
            print(e)

            if e.errno==1062:
                return {"error":"이미 즐겨찾기가 존재합니다."}, HTTPStatus.BAD_REQUEST
            elif e.errno==1452:
                return {"error":"해당 영화는 존재하지 않습니다."}, HTTPStatus.BAD_REQUEST
            else:
                return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE
        
        finally:
            cursor.close()
            connection.close()

    # 즐겨찾기삭제
    # 메소드 : delete
    # 데이터 : header:user_id토큰
    # result=
    @jwt_required(optional=False)
    def delete(self, movie_id):
        #user_id를 create_access_token(user_id)로 암호화 했다.
        #인증토큰을 복호화 한다.
        user_id=get_jwt_identity()

        try:
            # 데이터 인서트
            # db접속
            connection = get_connection()

            # 쿼리작성
            query='''delete from favorite
                    where userId=%s
                      and movieId=%s
                    ; '''

            record=(user_id, movie_id)

            # 커서
            cursor=connection.cursor()

            # 실행
            cursor.execute(query, record)

            # 커밋
            connection.commit()

            if cursor.rowcount >= 1:
                return {"result":"success"}, HTTPStatus.OK
            else:
                return {"error":"해당 영화의 즐겨찾기가 존재하지 않습니다."}, HTTPStatus.BAD_REQUEST

        except mysql.connector.Error as e:
            connection.rollback()
            
            print("Error code:", e.errno)        # error number
            print("SQLSTATE value:", e.sqlstate) # SQLSTATE value
            print("Error message:", e.msg)       # error message
            print(e)

            return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE
        
        finally:
            cursor.close()
            connection.close()

#개인화영화추천
# 경로 : /movie/recommend
class Recommend(Resource):
    # 영화추천
    # 메소드 : get
    # 데이터 : header:user_id토큰, params=?top=10
    # top=10 상위 10개 추천영화
    # result : 추천영화목록
    @jwt_required()
    def get(self):
        #1.클라이언트로부터 데이터를 받아온다.
        top=int(request.args['top'])

        #user_id를 create_access_token(user_id)로 암호화 했다.
        #인증토큰을 복호화 한다.
        user_id=get_jwt_identity()

        #2.추천을 위한 상관계수 데이터프레임을 읽는다.(코랩에서 작업한 파일)
        df_movie_correlations=pd.read_csv('data/movie_correlations.csv', index_col='title')
        #print(df_movie_correlations)

        #3.내 별점목록을 가져온다.
        try:
            # db접속
            connection = get_connection()

            query='''select a.userId, a.movieId, b.title, a.rating
                    from rating a join movie b
                        on a.movieId=b.id
                    where a.userId=%s
                    ;'''

            record=(user_id, )

            # 커서(딕셔너리 셋으로 가져와라)
            #select문은 dictionary=True 한다.
            cursor=connection.cursor(dictionary=True)

            # 실행
            cursor.execute(query, record)
            
            # 데이터fetch : select문은 아래함수를 이용해서 데이터를 가져온다.
            result_list=cursor.fetchall()
            #print(result_list)

            if len(result_list)==0:
                return {"error":"해당 사용자가 작성한 영화리뷰가 존재하지 않습니다."}, HTTPStatus.BAD_REQUEST

            #데이터프레임으로 변환한다.
            df_myRatings=pd.DataFrame(result_list)

            #4. 사용자의 별점을 가져왔으면 추천영화를 추출한다.
            #추천영화 작업을 자동화 하기 위한 파이프라인을 만든다.
            similar_movies_list = pd.DataFrame()
            #내가 본 영화들에 대한 추천영화들을 반복문을 사용하여 데이터프레임으로 만든다.
            for i in range(df_myRatings.shape[0]):
                movie_name=df_myRatings['title'][i]
                recom_movie=df_movie_correlations[movie_name].dropna().sort_values(ascending=False).to_frame()
                recom_movie.columns=['correlation']
                recom_movie['weight']=recom_movie['correlation'] * df_myRatings['rating'][i]
                #similar_movies_list=similar_movies_list.append(recom_movie)
                similar_movies_list=pd.concat([similar_movies_list, recom_movie])

            drop_index = df_myRatings['title'].to_list()
            #내가 본 영화는 데이터프레임에서 삭제한다.
            # for name in drop_index:
            #     if name in similar_movies_list.index:
            #         similar_movies_list.drop(name,axis=0, inplace=True)

            similar_movies_list.reset_index(inplace=True)
            #내가 본 영화는 데이터프레임에서 삭제한다.
            similar_movies_list=similar_movies_list.loc[~similar_movies_list['title'].isin(drop_index),]

            #추천영화가 중복되는 경우도 발생한다.
            #따라서 중복된 영화가 있을경우 웨이트가 높은 값으로만 추천한다.
            #영화이름별 웨이트가 가장 높은 데이터를 가져와서 웨이트로 정렬한다.
            similar_movies_list=similar_movies_list.groupby('title')['weight'].max().sort_values(ascending=False)
            #시리즈 넹...
            similar_movies_list=similar_movies_list.reset_index()

            #상위 top 개만 가져와라.. json으로 즉 딕셔너리로 변경
            result_recomm_list=similar_movies_list.iloc[0:top,].to_dict('records')

            return {"result":"success",
                    "count":len(result_recomm_list),
                    "items":result_recomm_list}, HTTPStatus.OK

        except mysql.connector.Error as e:
            print(e)
            return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE

        finally:
            # 자원해제
            #print('finally')
            cursor.close()
            connection.close()

#개인화영화추천(실시간)
# 경로 : /movie/recommend/realtime
class RecommendRealTime(Resource):
    # 영화추천(실시간)
    # 메소드 : get
    # 데이터 : header:user_id토큰, params=?top=10
    # top=10 상위 10개 추천영화
    # result : 추천영화목록
    @jwt_required()
    def get(self):
        #1.클라이언트로부터 데이터를 받아온다.
        top=int(request.args['top'])

        #user_id를 create_access_token(user_id)로 암호화 했다.
        #인증토큰을 복호화 한다.
        user_id=get_jwt_identity()

        #2.ITEM-BASED COLLABORATIVE FILTERING 상관계수를 구하기 위한 데이터를 가져온다.
        #3.내 별점목록을 가져온다.
        try:
            # db접속
            connection = get_connection()

            # 커서(딕셔너리 셋으로 가져와라)
            #select문은 dictionary=True 한다.
            cursor=connection.cursor(dictionary=True)

            #2.ITEM-BASED COLLABORATIVE FILTERING 상관계수를 구하기 위한 데이터를 가져온다.
            query='''select a.userId, a.movieId, b.title, a.rating
                    from rating a join movie b
                        on a.movieId=b.id
                    ;'''

            # 실행
            cursor.execute(query)
            
            # 데이터fetch : select문은 아래함수를 이용해서 데이터를 가져온다.
            result_list=cursor.fetchall()
            #print(result_list)
            
            if len(result_list)==0:
                return {"error":"영화리뷰 데이터가 존재하지 않습니다."}, HTTPStatus.BAD_REQUEST

            #데이터프레임으로 변환한다.
            df_movie_correlations=pd.DataFrame(result_list)
            #상관계수를 구하기 위해 pivot_table 한다.
            #df_movie_correlations=df_movie_correlations.pivot_table(values='rating',index='userId',columns='title',aggfunc='mean')
            df_movie_correlations=df_movie_correlations.pivot_table(values='rating',index='userId',columns='movieId',aggfunc='mean')
            #영화별로 50개 이상의 리뷰가 있는 영화의 상관계수를 구한다.
            df_movie_correlations=df_movie_correlations.corr(min_periods=50)
            #상관계수 데이터프레임을 csv파일로 저장한다.
            #df_movie_correlations.to_csv('data/movie_correlations.csv')

            #3.내 별점목록을 가져온다.
            query='''select a.userId, a.movieId, b.title, a.rating
                    from rating a join movie b
                        on a.movieId=b.id
                    where a.userId=%s
                    ;'''

            record=(user_id, )

            # 실행
            cursor.execute(query, record)
            
            # 데이터fetch : select문은 아래함수를 이용해서 데이터를 가져온다.
            result_list=cursor.fetchall()
            #print(result_list)

            if len(result_list)==0:
                return {"error":"해당 사용자가 작성한 영화리뷰가 존재하지 않습니다."}, HTTPStatus.BAD_REQUEST

            #데이터프레임으로 변환한다.
            df_myRatings=pd.DataFrame(result_list)

            #4. 사용자의 별점을 가져왔으면 추천영화를 추출한다.
            #추천영화 작업을 자동화 하기 위한 파이프라인을 만든다.
            similar_movies_list = pd.DataFrame()
            #내가 본 영화들에 대한 추천영화들을 반복문을 사용하여 데이터프레임으로 만든다.
            for i in range(df_myRatings.shape[0]):
                #movie_name=df_myRatings['title'][i]
                movie_name=df_myRatings['movieId'][i]
                recom_movie=df_movie_correlations[movie_name].dropna().sort_values(ascending=False).to_frame()
                recom_movie.columns=['correlation']
                recom_movie['weight']=recom_movie['correlation'] * df_myRatings['rating'][i]
                #similar_movies_list=similar_movies_list.append(recom_movie)
                similar_movies_list=pd.concat([similar_movies_list, recom_movie])

            #drop_index = df_myRatings['title'].to_list()
            drop_index = df_myRatings['movieId'].to_list()
            #내가 본 영화는 데이터프레임에서 삭제한다.
            # for name in drop_index:
            #     if name in similar_movies_list.index:
            #         similar_movies_list.drop(name,axis=0, inplace=True)

            similar_movies_list.reset_index(inplace=True)
            #내가 본 영화는 데이터프레임에서 삭제한다.
            #similar_movies_list=similar_movies_list.loc[~similar_movies_list['title'].isin(drop_index),]
            similar_movies_list=similar_movies_list.loc[~similar_movies_list['movieId'].isin(drop_index),]

            #추천영화가 중복되는 경우도 발생한다.
            #따라서 중복된 영화가 있을경우 웨이트가 높은 값으로만 추천한다.
            #영화이름별 웨이트가 가장 높은 데이터를 가져와서 웨이트로 정렬한다.
            #similar_movies_list=similar_movies_list.groupby('title')['weight'].max().sort_values(ascending=False)
            similar_movies_list=similar_movies_list.groupby('movieId')['weight'].max().sort_values(ascending=False)
            #시리즈 넹...
            similar_movies_list=similar_movies_list.reset_index()

            #상위 top 개만 가져와라.. json으로 즉 딕셔너리로 변경
            #result_recomm_list=similar_movies_list.iloc[0:top,].to_dict('records')

            recomm_movieIds = similar_movies_list.iloc[0:top,0].to_list()
            #print(recomm_movieIds)
            t = tuple(recomm_movieIds)

            query='''select count(b.movieId) review_cnt
                        ,convert(ifnull(avg(b.rating), 0), double) rating_avg 
                        ,a.id movieId
                        ,a.title
                        ,a.summary
                        ,convert(date(a.year), char) year
                        ,a.attendance
                    from movie a left join rating b
                        on a.id=b.movieId
                    where a.id in {}
                    group by a.id
                    order by rating_avg desc
                    ;'''.format(t)

            # 실행
            cursor.execute(query)
            
            # 데이터fetch : select문은 아래함수를 이용해서 데이터를 가져온다.
            result_list=cursor.fetchall()
            #print(result_list)

            # #가져온 추천영화목록에 추천순서, 가중치를 merge 한다.
            # #데이터프레임으로 변환한다.
            # df_movies_list=pd.DataFrame(result_list)
           
            return {"result":"success",
                    "count":len(result_list),
                    "items":result_list}, HTTPStatus.OK

            # return {"result":"success",
            #         "count":len(result_recomm_list),
            #         "items":result_recomm_list}, HTTPStatus.OK

        except mysql.connector.Error as e:
            print(e)
            return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE

        finally:
            # 자원해제
            #print('finally')
            cursor.close()
            connection.close()

