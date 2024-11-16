# pw_protector

### Docker compose
zazenes:
docker compose up --build

vgasnes:
docker compose down

### Mongo
da se povezes na mongo (lokalno):  
`mongosh --host localhost --port 27017 -u root -p example --authenticationDatabase admin`  
izpis users:
`db.users.find().pretty()`  


### REST API:

1. **Get all users passwords** 
`POST` http://localhost:5144/password/jernejtest  
**Request Body example:**
```json 
{
   "Username": "jernejtest",
   "MasterPassword": "mysecretpassword"
}
```

2. **Create user** 
`POST` http://localhost:5144/masterPassword  
   **Request Body example:**
```json 
{
   "Username": "jernejtest",
   "MasterPassword": "mysecretpassword"
}
```

3. **Add password to user**
`POST` http://localhost:5144/password  
   **Request Body example:**
```json 
{
  "Username": "jernejtest",
  "MasterPassword": "mysecretpassword",
  "Password": "password123",
  "Description": "facebook"
}
```
