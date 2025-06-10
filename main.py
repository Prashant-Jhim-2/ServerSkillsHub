from fastapi import FastAPI
from pydantic import BaseModel
import firebase_admin
from dotenv import load_dotenv
from firebase_admin import credentials, firestore
import bcrypt
from datetime import datetime ,timedelta,timezone
import os
import httpx

from passlib.pwd import genword
from mangum import Mangum


app = FastAPI()
load_dotenv()
from fastapi.middleware.cors import CORSMiddleware
RESENDAPI = os.getenv("RESEND_SECRET_KEY")
firebase_config = {
    "type": "service_account",
    "project_id": os.getenv("FIREBASE_PROJECT_ID"),
    "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
    "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace("\\n", "\n"),  # Fix multiline private key
    "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
    "client_id": os.getenv("FIREBASE_CLIENT_ID"),
    "auth_uri": os.getenv("FIREBASE_AUTH_URI"),
    "token_uri": os.getenv("FIREBASE_TOKEN_URI"),
    "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_X509_CERT_URL"),
    "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_X509_CERT_URL"),
    "universe_domain":os.getenv("UNIVERSE_DOMAIN")
}

cred = credentials.Certificate(firebase_config)
firebase_admin.initialize_app(cred)
print("FireBase Initialised")
db = firestore.client()
usersref = db.collection("users")



#Schema for Incoming Data in Request 
class Item(BaseModel):
    Email:str
    Password:str
class RegisterSchema(BaseModel):
    Email:str
    Password:str
    FullName:str 
class VerifySchema(BaseModel):
    id:str
class CheckEmailSchema(BaseModel):
    Email:str
class EmailIDSchema(BaseModel):
    Email:str
    FullName:str
class ProfileFetchSchema(BaseModel):
    id:str
class LoginSchema(BaseModel):
    Email:str
    Password:str
class AddCourseSchema(BaseModel):
    Details:dict

class CardFetchSchema(BaseModel):
    id:str

class QuestionSchema(BaseModel):
    Text:str
    Name:str
    CourseId:str
    ProfileId:str

class EducSchema(BaseModel):
    isStudent:bool
    Name:str
    Level:str
    State:str
    Country:str 
    Profile:str

class EditQuestionSchema(BaseModel):
    id:str
    Text:str

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # URL of the Next.js app
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
@app.get("/")
def root():
    print("i m working  fully")
    return {"status":True}
@app.post("/Check")
def root(items:Item):
    docref = usersref.stream()
    print(docref)
    return {"status":True}
#Endpoint to Check Email Exist if Then Send id or not Then Create Account for it
@app.post("/EmailID")
def root(RequestBody:EmailIDSchema):
    UserDetails = RequestBody.dict()
    Email = UserDetails["Email"]
    print(Email)
    query =  usersref.where("Email","==",Email)
    docs =  query.stream()
    data = []
    for doc in docs :
        data.append({"id":doc.id,**doc.to_dict()})
    if len(data) != 0:
        return {"status":True,"Email":data[0]["Email"],"Type":data[0]["Type"],"id":data[0]['id'],"FullName":data[0]["FullName"],"ImgSrc":data[0]['ImgSrc']}
    if len(data) == 0:
       
        password = genword(length=12)
        inbytespassword = password.encode("utf-8")
        hashed =  bcrypt.hashpw(inbytespassword,bcrypt.gensalt())
        hashed_str = hashed.decode("utf-8")
        details = {
        "Type":"Customer",
        "Email": Email ,
        "FullName":RequestBody.FullName,
        "Password":hashed_str,
        "ImgSrc":"https://firebasestorage.googleapis.com/v0/b/fosystem2-86a07.appspot.com/o/photos%2F3d-cartoon-character.jpg?alt=media&token=90e0d748-1074-4944-8302-32644c60407c"
        }
        print(details)
        senttodb =  usersref.add(details)
        idofdoc =senttodb[1].id
        return {"status":True,"Email":details["Email"],"Type":details["Type"],"id":idofdoc,"FullName":details['FullName'],"ImgSrc":details["ImgSrc"]}
        
        
    
#Endpoints To Fetch All Course Card 
@app.get("/Courses")
async def root():
    docs = db.collection("courses").stream()
    data = []
    for doc in docs :
        arr = {"id":doc.id,**doc.to_dict()}
        data.append(arr)
    return {"status":True,"data":data}
       

#Endpoint To Add Course
@app.post("/AddCourse")
def root(RequestBody:AddCourseSchema):
    Details = RequestBody.Details
    print(Details)
    usersref = db.collection("courses")
    sendtodb = usersref.add(Details)
    return {"status":True}


#Endpoint to Check Email Exist in Database or Not 
@app.post("/CheckEmail")
def  root(data:CheckEmailSchema):
    Email = data.Email
    print(Email)
    query =  usersref.where("Email","==",Email)
    docs =  query.stream()
    data = []
    id = None 
    for doc in docs :
        arr = {"id":doc.id,**doc.to_dict()}
        id = doc.id 
        data.append(arr)
    print(len(data))
    if len(data) != 0 :
        return {"status":True,"id":id}
    if len(data) == 0 :
        return {"status":False}
    
#EndPoint To Fetch Profile Data 
@app.post("/Profile")
def root(Profile:ProfileFetchSchema):
    body = Profile.dict()
    print(body)
    docref = db.collection("users").document(body['id'])
    doctt = docref.get()
    dataarr = {"id":doctt.id ,**doctt.to_dict()}
    if doctt.exists == True :
      return {"status":True ,"data":dataarr}
    if doctt.exists == False:
        return {"status":False}
    
    
 


class VerifyInstance(BaseModel):
    Email:str
    Change:str
    Details:dict
   
@app.post("/VerifyInstance")
def root(RequestBody:VerifyInstance):
    details = RequestBody.dict()
    currenttime = datetime.now(timezone.utc)
    newtime = currenttime + timedelta(minutes=15)
    obj = None 
    if details["Change"] == "Details":
       obj = {"Email":details["Email"],"Type":"Change","Details":details["Details"],"Created":currenttime,'Expired':newtime}
    if details["Change"] == "Verify":
       obj = {"Email":details["Email"],"Type":"Register","Created":currenttime,'Expired':newtime}

    
    docref = db.collection('temp').add(obj)
    id = docref[1].id 
    print(id)
    return {"status":True,"id":id}

class UpdateSchema(BaseModel):
    Email:str
    Details:dict
@app.post("/UpdateDetails")
def root(RequestBody:UpdateSchema):
    body = RequestBody.dict()
    details = body["Details"]
    colref = db.collection("users")
    query= colref.where("Email","==",body['Email'])
    docs = query.stream()
    id = None 
    for doc in docs :
        id = doc.id 

    docref  = colref.document(id) 
    Update = docref.update({"FullName":details["FullName"],"Password":details["Password"]})
    return {"status":True}
   
@app.get("/Verify/{id}")
def root(id:str):
   docref = db.collection("temp").document(id)
   doc = docref.get()
   docdata = doc.to_dict()
   print(docdata)
   currenttime = datetime.now(timezone.utc)
   expiredtime = docdata.get("Expired")
   Email = docdata.get("Email")
   Type = docdata.get("Type")
   details = "" 
   if Type == "Change":
       details = docdata.get("Details")
   
   if doc.exists == True  :
       print(expiredtime,currenttime)
       if expiredtime > currenttime:
        return {"status":True,"Details":details,"Type":Type,"Email":Email}
       else:
           return {"status":False}
   else:
       return {"status":False}
   
@app.get("/Forget/{id}")
def root(id:str) :
    docref = db.collection('Forget').document(id)
    doc = docref.get()
    docdata = doc.to_dict()
    currenttime = datetime.now(timezone.utc)
    expiredtime = docdata.get("Expired")
    Email = docdata.get("Email")

    if doc.exists :
        if expiredtime > currenttime : 
            return {"status":True,"Email":Email}   
        else:
            return {"status":False} 
    else:
        return {"status":False}
@app.get("/CheckID/{id}")
def root(id:str):
    docref = db.collection('users').document(id)
    doc = docref.get()
    docdata = doc.to_dict()
    if doc.exists == False :
        return {"status":False}
    if doc.exists == True :
     data = {'id':id,**docdata}
     return {'status':True,"Details":data}

#Endpoint To Login 
@app.post("/Login")
def root(RequestBody:LoginSchema):
    Email = RequestBody.Email
    query =  usersref.where("Email","==",Email)
    docs =  query.stream()
    data = []
    
    for doc in docs :
         arr = {"id":doc.id,**doc.to_dict()}
         data.append(arr)
    if len(data) > 0 :
        details = data[0]
        status = bcrypt.checkpw(RequestBody.Password.encode('utf-8'), details["Password"].encode("utf-8"))
        if status :
         return {"status":True,"Type":details['Type'],"id":details["id"],"FullName":details["FullName"],"ImgSrc":details['ImgSrc']}
        else :
            return {"status:False"}
    
    if len(data) <= 0 :
        return {"status":False}
    
#Endpoint To Fetch Card Details 
@app.get("/Card/{id}")
def root(id:str):
    
    docref = db.collection("courses").document(id)
    doctt = docref.get()
    dataarr = {"id":doctt.id ,**doctt.to_dict()}
    print(dataarr)
    return {"status":True,"data":dataarr}

class EditCourseSchema(BaseModel):
    id:str
    data:dict
#Endpoint to Update The Card Details 
@app.post("/UpdateCard")
def root(RequestBody:EditCourseSchema):
    Details = RequestBody.dict()
    Data = Details['data']
    docref = db.collection("courses").document(Details['id'])
    resp = docref.update({'Name':Data['Name'],'Description':Data['Description'],'ImgSrc':Data['ImgSrc'],'content':Data["Content"] })
    print(resp)
    return {"status":True}

    
#Endpoint to Build New Video Page or Give Existing one id 
@app.post("/Content")
def root(RequestBody:VerifySchema):
    details = RequestBody.dict()
    colref = db.collection("Content")
    query = colref.where("CourseID","==",details['id'])
    docs = query.stream()
    data = []
    for doc in docs :
        data.append({"id":doc.id})
    
    if len(data) == 0:
        coursecontent = {
            "CourseID":details['id'],
            "Videos":[]
        }
        sendtodb = colref.add(coursecontent)
        idofdoc = sendtodb[1].id 
        return {"status":True,"id":idofdoc}
    if len(data) != 0:
        idofdoc = data[0]['id']
        return {"status":True,"id":idofdoc}
        
class VideoSchema(BaseModel):
    Name : str 
    Description:str
    urlofvideo:str
    CourseID : str
    urlofThumbnail:str
#Endpoint for Video Content
@app.post("/Video")
def root(RequestBody:VideoSchema):
    details = RequestBody.dict()
    colref = db.collection("Videos")
    sendtodb = colref.add(details)
    idofdoc = sendtodb[1].id 
    if idofdoc != None :
        return {"status":True ,"id":idofdoc}
    if idofdoc == None : 
        return {"status":False}
    
@app.get("/GetContent/{id}")
def root(id:str):
    docref = db.collection("Content").document(id)
    doc = docref.get()
    arrofdata = doc.to_dict()
    return {"status":True,"data":arrofdata}



@app.get("/GetCourse/{id}")
def root(id:str):
    docref = db.collection("courses").document(id)
    doc = docref.get()
    arrofdata = doc.to_dict()
    if arrofdata != None :
        return {"status":True,"data":arrofdata}
    if arrofdata == None :
        return {"status":False}
@app.get("/GetVideos/{id}")
def root(id:str):
    colref = db.collection("Videos")
    query = colref.where("CourseID",'==',id)
    docs = query.stream()
    data = [] 
    for doc in docs : 
        data.append({"id":doc.id , **doc.to_dict()})
    return {'status' : True , "data" : data}
        
#Endpoint to Get Video 
@app.get("/VideoDetail/{id}")
def root(id:str):
    docref = db.collection("Videos").document(id)
    doc = docref.get()
    arrofdata = doc.to_dict()
    return {"status":True,"data":arrofdata}

#EndPoint to Register in Database
@app.post("/Register")
def root(Requestbody:RegisterSchema):
    details = {
        "Type":"Customer",
        "Email": Requestbody.Email ,
        "FullName":Requestbody.FullName,
        "Password":Requestbody.Password,
        "ImgSrc":"https://firebasestorage.googleapis.com/v0/b/fosystem2-86a07.appspot.com/o/photos%2F3d-cartoon-character.jpg?alt=media&token=90e0d748-1074-4944-8302-32644c60407c"
    }
    sendtodb = usersref.add(details)
    idofdoc = sendtodb[1].id
    return {"status":True,"id" :idofdoc}

@app.post("/Education")
def root(RequestBody:EducSchema):
    Details = RequestBody.dict()
    print(Details)
    user = db.collection("EducationDetails")
    sendtodb = user.add(Details)
    idofdoc = sendtodb[1].id 
    if idofdoc != None :
        return {"status":True}
    if idofdoc == None :
        return {"status":False}
    

@app.post("/PostQuestion")
def root(RequestBody:QuestionSchema):
    Details = RequestBody.dict()
    userref = db.collection("Questions")
    sendtodb = userref.add(Details)
    idofdoc = sendtodb[1].id 
    if idofdoc != None:
        return {"status":True,"id":idofdoc}
    if idofdoc == None :
        return {"status":False}

@app.get("/Questions/{id}")
def root(id:str):
    print(id)
    usersref = db.collection("Questions")
    query =  usersref.where("CourseId","==",id)
    docs =  query.stream()
    data = []
    for doc in docs :
         arr = {"id":doc.id,**doc.to_dict()}
         data.append(arr)
    if len(data) != 0:
        return {"status":True,"data":data}
    if len(data) == 0:
        return {"status":False}
    
@app.post("/DeleteQuestion")
def root(RequestBody:VerifySchema):
    Details  = RequestBody.dict()
    print(Details)
    docref = db.collection("Questions").document(Details["id"])
    docref.delete()
    return {"status":True}


@app.post("/EditQuestion")
def root(RequestBody:EditQuestionSchema):
    Details = RequestBody.dict()
    print("Update ")
    print(Details)
    docref = db.collection("Questions").document(Details["id"])
    docref.update({"Text":Details["Text"]})
    return {"status":True}

class ReplySchema(BaseModel):
    Name:str
    ProfileId:str
    Text:str
    QuestionId:str 

@app.post('/Reply')
def root(RequestBody:ReplySchema):
    details = RequestBody.dict()
    print(details)
    colref = db.collection("Replies")
    sendtodb = colref.add(details)
    return {"status":True}

@app.get("/GetReplies/{id}")
def root(id:str):
    colref = db.collection("Replies")
    query = colref.where("QuestionId","==",id)
    docs = query.stream()
    data = []
    for doc in docs :
        data.append({"id":doc.id,**doc.to_dict()})

    print(data)
    return {"status":True,"data":data}

@app.get("/DeleteReply/{id}")
def root(id:str):
    docref = db.collection("Replies").document(id)
    docref.delete()
    return {"status":True}

# Enrolled EndPoint 
class EnrolledSchema(BaseModel):
    CourseName:str 
    CourseID:str 
    ProfileName:str 
    ProfileID:str 
    AccessType:str 

@app.post("/Enrolled")
def root(RequestBody:EnrolledSchema):
    details = RequestBody.dict()
    sendtodb = db.collection("enrolled").add(details)
    return {"status":True}

@app.get('/LastChat/{id}')
def root(id:str):
    colref = db.collection("communitychats")
    query = colref.where("Courseid","==",id)
    docs = query.stream()
    data = []
    for doc in docs:
        details = {"id": doc.id, **doc.to_dict()}
        data.append(details)    
    if len(data) != 0 :
        return {"status":True,"data":data[0]}  
    if len(data) == 0 :
        return {"status":False,"data":[]}
   
@app.get("/GetEnrolled/{id}")
def root(id:str):
    print(id)
    colref = db.collection("Payments")
    query = colref.where("ProfileID","==",id).where("status","==","Completed")
    docs = query.stream()
    dataarr = []
    for doc in docs :
        dataarr.append({"id":doc.id,**doc.to_dict()})
    print(dataarr)
    return {"status":len(dataarr) != 0,"data":dataarr}

# Endpoint to Register Payment in Database 
class PaymentSchema(BaseModel):
    SessionID:str
    PaymentID:str
    status:str
    CourseName:str
    ProfileID:str
    CourseID:str
    Name:str
    Email:str
    Payments:list
    Amount:str
    Currency:str 
    DateofPurchase:str
    mode:str
    Active:bool
   
@app.post("/SuccessPayment")
def root(RequestBody:PaymentSchema):
    Details = RequestBody.dict()
    print(Details)
    sendtodb = db.collection("Payments").add(Details)
    id = sendtodb[1].id 
    return {"status":True,"id":id}
@app.get("/Payments/{id}")
def root(id:str):
    colref = db.collection("Payments")
    query = colref.where("ProfileID",'==',id).where("status",'==',"Completed")
    docs = query.stream()
    dataarr = []
    for doc in docs :
        dataarr.append({"id":doc.id,**doc.to_dict()})
    return {"status":len(dataarr) != 0 , "data":dataarr}
class PaymentDetails(BaseModel):
    id :str
@app.post("/PaymentDetails")
def root(RequestBody:PaymentDetails):
    details = RequestBody.dict()
    id = details['id']
    colref = db.collection("Payments").document(id)
    doc = colref.get()
    dataarr = doc.to_dict()
    return {"status":True,'data':dataarr}
@app.get("/Payment/{id}")
def root(id:str):
    colref = db.collection("Payments")
    query = colref.where("PaymentID",'==',id)
    docs = query.stream()
    data = []
    for doc in docs : 
        data.append({"id":doc.id,**doc.to_dict()})
    return {"status":True,"data":data}
class UpdatePaymentSchema(BaseModel):
    Details:dict


@app.get('/GetEnrolledStudents/{id}')
def root(id:str):
    colref = db.collection("Payments")
    query = colref.where("CourseID",'==',id).where("status",'==',"Completed")
    docs = query.stream()
    dataarr = []
    for doc in docs :
        details = doc.to_dict()
        colref = db.collection("users").document(details["ProfileID"])
        doc = colref.get()
        data = doc.to_dict()
        newdetails = {
            "id":doc.id,
            "FullName":data["FullName"],
        }
        dataarr.append(newdetails)
        
    print(dataarr)
    return {"status":len(dataarr) != 0,"data":dataarr}


@app.post("/UpdatePayment")
def root(RequestBody:UpdatePaymentSchema):
    colref = db.collection('Payments')
    Request = RequestBody.dict()
    Details = Request['Details'] 
    print(Details)
    if Details["Type"] == "Success" :
        print("i am Successful payment")
        query = colref.where("PaymentID",'==',Details['id'])
        docs = query.stream()
        id = 'im'
        for doc in docs :
           id = doc.id
        if id != 'im':
            docref = db.collection("Payments").document(id)
            docupdate = docref.update({"status":"Completed","Active":True})
    
       
    if Details["Type"] == "Subscription":
        query = colref.where("PaymentID",'==',Details['id'])
        docs = query.stream()
        id = 'im'
        for doc in docs :
           id = doc.id
        if id != 'im':
            docref = db.collection("Payments").document(id)
            docupdate = docref.update({"status":"Completed","Active":True,"Payments":Details["data"]})
    
    

    if Details['Type'] == 'Recurring':
        query = colref.where("PaymentID",'==',Details['id'])
        docs = query.stream()
        id = 'im'
        for doc in docs :
           id = doc.id
        if id != 'im':
            docref = db.collection("Payments").document(id)
            status = Details['Active'] == True
            compornot = 'Pending'
            if status == True :
                status = "Completed"
            if status == False :
                status = "Failed"
            docupdate = docref.update({"status":compornot,"Active":Details['Active']})
            print(docupdate)
            

    
       

    if Details["Type"] == 'Checkout' :
         print("i m checkout")
         query = colref.where("SessionID",'==',Details['id'])
         docs = query.stream()
         id = ''
         for doc in docs :
            id = doc.id 
         docref = db.collection("Payments").document(id)
         docupdate = docref.update({'mode':Details["mode"],"Amount":Details["Amount"],"DateofPurchase":Details["DateofPurchase"],"Currency":Details['Currency'],"Name":Details['Name'],"Email":Details["Email"],"PaymentID":Details["PaymentID"]})
    return {"status":True}

class RefundSchema(BaseModel):
    ProfileID:str
    PaymentID:str
    Reason:str
    Approved:str

@app.post("/Refund")
def root(RequestBody:RefundSchema):
    Details = RequestBody.dict()
    sendtodb = db.collection("refunds").add(Details)
    return {"status":True}
class RefundCheck(BaseModel):
    UserID:str
    PaymentID:str
@app.post("/RefundExist")
def root(RequestBody:RefundCheck):
    Details = RequestBody.dict()
    print(Details)
    colref = db.collection("refunds")
    query = colref.where("ProfileID",'==',Details["UserID"]).where("PaymentID",'==',Details["PaymentID"])
   
    docs = query.stream()
    data = []
    for doc in docs :
        data.append({"id":doc.id,**doc.to_dict()})
    if len(data) != 0 :
        print(data)
        return {"status":True , "data":data[0]}
    if len(data) == 0 :
        return {"status":False}
class RefundEdit(BaseModel):
    id:str
    user:str
    Reason:str
@app.post("/RefundEdit")
def root(RequestBody:RefundEdit):
    Details = RequestBody.dict()
    docref = db.collection("refunds").document(Details["id"])
    doc = docref.get()
    dataarr = doc.to_dict()
    if dataarr["ProfileID"] == Details["user"]:
        docref.update({"Reason":Details["Reason"]})
        return {"status":True}
    else:
        return {"status":False}
class RefundDelete(BaseModel):
    id:str
    user:str
@app.post("/RefundDelete")
def root(RequestBody:RefundDelete):
    Details = RequestBody.dict()
    print(Details)
    docref = db.collection("refunds").document(Details["id"])
    doc = docref.get()
    dataarr = doc.to_dict()
    if dataarr["ProfileID"] == Details["user"]:
        docref.delete()
        return {"status":True}
    else:
        return {"status":False}
class ForgetSchema(BaseModel):
    Email:str
@app.post("/ForgetPassword")
def root(RequestBody:ForgetSchema):
    details = RequestBody.dict()
    currenttime = datetime.now(timezone.utc)
    newtime = currenttime + timedelta(minutes=15)
    obj = {"Email":details["Email"],"Type":"Forget","Created":currenttime,'Expired':newtime}
    sendtodb = db.collection("Forget").add(obj)
    id = sendtodb[1].id 
    return {'status':True,"id":id}

class ChangePassword(BaseModel):
    Email:str
    Password:str
@app.post("/ChangePassword")
def root(RequestBody:ChangePassword):
    details = RequestBody.dict()
    print(details)
    colref = db.collection("users")
    query = colref.where("Email",'==',details["Email"])
    docs = query.stream()
    id = ""
    for doc in docs :
        id = doc.id 
    docref = db.collection("users").document(id) 
    update = docref.update({"Password":details["Password"]})
    return {"status":True}


#Endpoint for users
@app.get('/users')
def root():
    docs = db.collection("ProfessorApplications").stream()
    data = []
    for doc in docs :
        data.append({"id":doc.id,**doc.to_dict()})
    return {"status":True,"data":data}

#Endpoint for refunds request 
@app.get("/Refunds")
def root():
    docs = db.collection("refunds").stream()
    data = []
    for doc in docs :
        data.append({"id":doc.id,**doc.to_dict()})
    return {"status":True,"data":data}

class AssignSchema(BaseModel):
    id:str
    Type:str 
    idofcard:str

#Endpoint to Assign New Type
@app.post("/Assign")
def root(RequestBody:AssignSchema):
    details = RequestBody.dict()
    docref = db.collection('users').document(details['id'])
    doc1 = docref.get()
    docref2 = db.collection("ProfessorApplications").document(details['idofcard'])
    doc2 = docref2.get()

    if doc1.exists == True & doc2.exists == True:
        updatedoc = docref.update({"Type":details['Type']})
        updatedoc2 = docref2.update({"Approved":True,"Type":details["Type"]})
        print(updatedoc,updatedoc2)
        return {"status":True}
    else :
        return {'status':False}
    
    

#Endpoint to delete User 
@app.get("/deleteuser/{id}")
def root(id:str):
    colref = db.collection('ProfessorApplications')
    docref = colref.document(id) 
    deletedoc = docref.delete()
    print(deletedoc)
    docs = colref.stream()
    data = []
    for doc in docs :
        data.append({"id":doc.id,**doc.to_dict()})
    return {"status":True,"data":data}

class ProfessorApplication(BaseModel):
    Data:dict 

@app.post("/ProfessorApplication")
def root(RequestBody:ProfessorApplication):
    body = RequestBody.dict()
    docref = db.collection("ProfessorApplications").add(body['Data'])
    id = docref[1].id 
    print(id)
    return {"status":True}

@app.get("/ProfessorDetails/{id}")
def root(id:str):
    print(id)
    colref = db.collection("ProfessorApplications")
    query = colref.where("idofuser",'==',id)
    docs = query.stream()
    data = ''
    for doc in docs :
        data = {"id":doc.id,**doc.to_dict()}
    return {"status":True,"data":data}

class Changes(BaseModel):
    data:dict
    id:str
    Type:str

@app.post("/Changes")
def root(RequestBody:Changes):
    body = RequestBody.dict()
    data = body['data']
    docref = db.collection("ProfessorApplications").document(body['id'])
    doc = docref.get()
    arrofdata = doc.to_dict()
    if body["Type"] == "Ed" : 
        updated = []
        arrneeded = arrofdata['Educationdetails']
        for doc in arrneeded : 
            if doc['idofcard'] == data['idofcard'] : 
                updated.append(data)
            else :
                updated.append(doc)
        updatedoc = docref.update({"Educationdetails":updated})
        return {"status":True }
    
    if body["Type"] == "Work":
        updated = []
        arrneeded = arrofdata['Work']
        for doc in arrneeded : 
            if doc['idofcard'] == data['idofcard'] : 
                updated.append(data)
            else :
                updated.append(doc)
        updatedoc = docref.update({"Work":updated})
        return {"status":True }
    
    if body['Type'] == "Cert":
        updated = []
        arrneeded = arrofdata['Certifications']
        for doc in arrneeded : 
            if doc['idofcard'] == data['idofcard'] : 
                updated.append(data)
            else :
                updated.append(doc)
        updatedoc = docref.update({"Certifications":updated})
        return {"status":True }
    
    
    
@app.get("/RefundApproval/{id}")
def root (id:str):
    docref = db.collection('refunds').document(id)
    # To Check Particular Refund Application Exist
    doc = docref.get()
    arrofdata = doc.to_dict()
    if arrofdata != None :
        updatedoc = docref.update({"Approved":"Approved"})
        return {"status" : True}
    if arrofdata == None : 
        print("immmmm")
        return {"status":False}



@app.get("/RefundCancel/{id}")
def root (id:str):
    docref = db.collection('refunds').document(id)
    # To Check Particular Refund Application Exist
    doc = docref.get()
    arrofdata = doc.to_dict()
    if arrofdata != None :
        updatedoc = docref.update({"Approved":"Declined"})
        return {"status" : True}
    if arrofdata == None : 
        print("immmmm")
        return {"status":False}

@app.get("/DeleteCourse/{id}")
def root(id:str):
    docref = db.collection("courses").document(id) 
    docref.delete()
    return {"status":True}

class ChatSchema(BaseModel):
    details:dict 
@app.post("/CheckChatID")
def root(RequestBody:ChatSchema):
    body = RequestBody.dict() 
    detailsofchat = body['details']
    print(detailsofchat)

   # Part in which check database whether it can find user1 and user2 in chat database
    docref = db.collection("chats").where("User1","==",detailsofchat["User1"]).where("User2",'==',detailsofchat["User2"])
    docs = docref.stream()
    id = None 
    for doc in docs:
        id = doc.id 
   
    if id  != None :
      return {'status':True,"id":id}

    
    docref2 = db.collection('chats').where("User1",'==',detailsofchat['User2']).where("User2",'==',detailsofchat["User1"])
    docs2 = docref2.stream()
    id2 = None 
    for doc in docs2:
        id2 = doc.id 
    if id2 != None :
        return {"status":True,"id":id2}
    
    if id == None  and id2 == None : 
        details = {
            "User1LastSeen":0,
            "User2LastSeen":0,
            "User1Typing":False,
            "User2Typing":False ,
            "User1":detailsofchat['User1'],
            "User2":detailsofchat['User2'],
            "Chat":[],
            "NewMessages1":False,
            "NewMessages2":False,
        }
        adddoc = db.collection('chats').add(details)
        idofdoc = adddoc[1].id
        print(idofdoc)
        return {'status':True,"id":idofdoc}
    
@app.get('/Chat/{id}')
def root(id:str):
    docref = db.collection('chats').document(id)
    doc = docref.get() 
    if doc.exists == True :
        data = doc.to_dict()
        return {"status":True,"Data":data}
    if doc.exists == False : 
        return {'status':False}


@app.post("/SendCommunityChat")
def root(RequestBody:ChatSchema):
    body = RequestBody.dict()
    details = body['details']
    docref = db.collection('communitychats').add(details)
    return {'status':True,'id':docref[1].id}
    
@app.get("/CommunityChats/{id}")
def root(id: str):
    print(id)
    colref = db.collection('communitychats')
    query = colref.where("Courseid", "==", id)
    docs = query.stream()
    data = []
    for doc in docs:
        details = {"id": doc.id, **doc.to_dict()}
        data.append(details)
    return {'status': len(data) != 0, "Data": data}



@app.post('/MarkImportant')
def root(RequestBody:ChatSchema):
    body = RequestBody.dict()
    details = body['details']
    print(details)
    docref = db.collection('communitychats').document(details['Courseid'])
    doc = docref.get()
    if doc.exists == True :
        markedimp = {
            "FullName":details['FullName'],
            "id":details['id'],
        }
        updatedoc = docref.update({"MarkedImp":markedimp})
        return {'status':True}
        
    if doc.exists == False :
        return {'status':False}


@app.post('/DeleteCommunityChat')
def root(RequestBody:ChatSchema):
    body = RequestBody.dict()
    details = body['details']
    print(details)
    docref = db.collection('communitychats').document(details['Chatid'])
    doc = docref.get()
    if doc.exists == True :
       data = doc.to_dict()
       if data['Profile'] == details['id'] :
            docref.delete()
            return {'status':True}
       else:
            return {'status':False}
        
    if doc.exists == False :
        return {'status':False}
@app.get("/AllUsers")
def root():
    docref = db.collection("users")
    docs = docref.stream()
    data = []
    for doc in docs :
        dataofuser = doc.to_dict()
        details = {
            "id":doc.id ,
            "FullName":dataofuser["FullName"],
            "ImgSrc":dataofuser["ImgSrc"]
        }
        data.append(details)
    
    return {'status':True,"data":data}

class AlertSchema(BaseModel):
    By:str
    ByFullName:str
    Page:str
    User:str
    Type:str 
    time:str
    Message:str
@app.post('/SendAlert')
def root(RequestBody:AlertSchema):
    details = RequestBody.dict()
    newdetails = {**details,"created":firestore.SERVER_TIMESTAMP}
    docsave = db.collection('alerts').add(newdetails)
    id = docsave[1].id 
    return {'status':True}


@app.get("/ClearAlerts/{id}")
def root(id:str):
    docs = db.collection('alerts').where("User","==",id).stream()
    count = 0 
    for doc in docs :
        doc.reference.delete()
        count += 1 

    print(count)
    return {'status':True}


@app.get('/Alerts')
def root():
    docref = db.collection('alerts')
    docs = docref.stream() 
    Data = [] 
    for doc in docs :
       
        details = {
            "id":doc.id ,
            **doc.to_dict()
        }
        Data.append(details)


    return {'status':True,"Data":Data}
@app.get("/Chats/{id}")
def root(id:str):
    print(id)
    docref1 = db.collection("chats").where("User1",'==',id)
    docs1 = docref1.stream() 
    data1 = []
    docref2 = db.collection('chats').where("User2",'==',id)
    docs2 = docref2.stream()
    data2 = []

    for doc in docs1 : 
        dataofuser = doc.to_dict()
        details = {
            "id":doc.id,
            "User1":dataofuser['User1'],
            "User2":dataofuser["User2"],
            "User1LastSeen":dataofuser["User1LastSeen"],
            "User2LastSeen":dataofuser["User2LastSeen"]
             
        }
        data1.append(details)
    
    for doc in docs2 : 
        dataofuser = doc.to_dict()
        details = {
            "id":doc.id,
            "User1":dataofuser['User1'],
            "User2":dataofuser["User2"],
            "User1LastSeen":dataofuser["User1LastSeen"],
            "User2LastSeen":dataofuser["User2LastSeen"]
             
        }
        data2.append(details)
    
    print(data1,data2)

    if len(data1) != 0 :
        return {"status":True,"data":data1}
    if len(data2) != 0 :
        return {"status":True,"data":data2}
    if len(data1) == 0 and len(data2) == 0 :
        return {"status":False}




    





class SendChatSchema(BaseModel):
    id:str
    chat: list 
    idofuser:str
@app.post("/SendChat")
def root(RequestBody:SendChatSchema):
    body = RequestBody.dict()
    docref = db.collection('chats').document(body['id'])
    doc = docref.get()
    if doc.exists ==  True :
        data = doc.to_dict()
        if data['User1'] == body['idofuser'] :
            updatedoc = docref.update({"NewMessages2":True})
        if data['User2'] == body['idofuser'] :
            updatedoc = docref.update({"NewMessages1":True})

       
        update = docref.update({"Chat":body['chat']})
        return {'status':True}
    if doc.exists == False:
        return {"status":False}

class DeleteSchema(BaseModel):
    id:str
    arr:list
@app.post('/DeleteChat')
def root(RequestBody:DeleteSchema):
    body = RequestBody.dict()
    docref = db.collection('chats').document(body['id'])
    doc = docref.get() 
    if doc.exists == True :
        update = docref.update({"Chat":body['arr']})
        return {'status':True}
    if doc.exists == False :
        return {'status':False}
    
class TypingSchema(BaseModel):
    idofchat:str
    idofuser:str
    status:bool

@app.post("/Typing")
def root(RequestBody:TypingSchema):
    body = RequestBody.dict()
    docref = db.collection("chats").document(body['idofchat'])
    doc = docref.get()
    if doc.exists == True :
        data = doc.to_dict()
        user1 = data['User1']
        user2 = data['User2']
        if user1 == body['idofuser'] : 
            update = docref.update({"User1Typing":body['status']})
            return {'status':True}
        if user2 == body['idofuser'] :
            update = docref.update({'User2Typing':body['status']})
            return {"status":False}

class OnlineSchema(BaseModel):
    idofuser:str
    idofchat:str
    lastseen:int
@app.post("/Online")
def root(RequestBody:OnlineSchema):
    body = RequestBody.dict()
    print(body)
    docref = db.collection('chats').document(body['idofchat'])
    doc = docref.get()
    if doc.exists == True :
        data = doc.to_dict()
       
        if data['User2'] == body["idofuser"]:
            update = docref.update({"User2LastSeen" : body['lastseen']})
            return {'status':True}
        if data['User1'] == body["idofuser"]:
            update = docref.update({"User1LastSeen" : body['lastseen']})
            return {'status':True}
        
    if doc.exists == False:
        return {'status':False}
    

class NewMessages(BaseModel):
    idofuser :str 
    idofchat :str

@app.post("/Seen") 
def root(RequestBody:NewMessages):
    body = RequestBody.dict()
    docref = db.collection('chats').document(body['idofchat'])
    doc = docref.get()
    if doc.exists == True :
        data = doc.to_dict()
        if data['User1'] == body['idofuser'] :
            updatedoc = docref.update({"NewMessages1":False})
            print('i m working')
            return {'status':True}
        if data['User2'] == body['idofuser'] :
            updatedoc = docref.update({"NewMessages2":False})
            print('i m working')
            return {'status':True}
    if doc.exists == False:
        return {'status':False}
    
class ChangeProfileImageSchema(BaseModel):
    id:str
    ImgSrc:str
@app.post("/ChangeProfileImage")
def root(RequestBody:ChangeProfileImageSchema):
    body = RequestBody.dict()
    print(body)
    docref = db.collection('users').document(body['id'])
    doc = docref.get()
    if doc.exists == True :
        updatedoc = docref.update({"ImgSrc":body['ImgSrc']})
        return {'status':True}
    if doc.exists == False:
        return {'status':False}
    
class EmailPostSchema(BaseModel):
    email:str
    domain:str
@app.post('/send-email')
async def root(RequestBody:EmailPostSchema):
    body = RequestBody.dict()
    print(body)
    id = body['email']
    Domain = body['domain']
    url = "https://api.resend.com/emails"

    headers = {
        "Authorization": f"Bearer {RESENDAPI}",
        "Content-Type": "application/json",
    }

    data = {
        "from": "notifications@prashantjhim.xyz",  
        "to": [id],
        "subject": "You have a new message!",
        "html": f"""
            <div style="font-family: Arial, sans-serif;">
                <h2>Skillshub 📝</h2>
                <pYou're receiving this email because you have an account on Skillshub.</p>
                <a href={Domain} style="display: inline-block; margin-top: 10px; padding: 10px 20px; background-color: #4f46e5; color: white; text-decoration: none; border-radius: 5px;">View Message</a>
                <p style="margin-top: 20px; font-size: 12px; color: #999;">Thank you for using Skillshub📝 </p>
            </div>
        """,
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=headers, json=data)
    
    if response.status_code == 200:
        return {"message": "Email sent successfully!"}
    else:
        return {"error": response.text}



handler = Mangum(app)
